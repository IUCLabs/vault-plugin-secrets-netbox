package netbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// netboxConfig is the connection to NetBox plus the seeded admin token the
// engine authenticates with.
type netboxConfig struct {
	NetboxURL string `json:"netbox_url"`
	// Token is the seeded admin credential (write-only from the API). For v2
	// tokens this is the full "nbt_<key>.<secret>" string; for v1 the bare
	// 40-char value.
	Token string `json:"token"`
	// AdminUserID / AdminTokenID identify the seeded token so config/rotate can
	// mint a replacement for the same user and delete the old token. Optional for
	// v2 (auto-discovered from the key); required for v1 rotation.
	AdminUserID  int `json:"admin_user_id"`
	AdminTokenID int `json:"admin_token_id"`
	// TokenVersion is the NetBox token version to request when minting (default
	// 2). Set to 1 when the NetBox server has no API_TOKEN_PEPPERS configured.
	TokenVersion          int    `json:"token_version"`
	CACert                string `json:"ca_cert"`
	TLSSkipVerify         bool   `json:"tls_skip_verify"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
}

func pathConfig(b *netboxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "netbox",
			OperationSuffix: "config",
		},
		Fields: map[string]*framework.FieldSchema{
			"netbox_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the NetBox server, e.g. https://netbox.example.com.",
				Required:    true,
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Seeded NetBox admin API token used to mint per-user tokens. Write-only. v2: the full nbt_<key>.<secret> string; v1: the bare 40-char value.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Admin Token",
					Sensitive: true,
				},
			},
			"admin_user_id": {
				Type:        framework.TypeInt,
				Description: "NetBox user id of the seeded admin token, so config/rotate can reissue it. Auto-discovered for v2 tokens if omitted.",
			},
			"admin_token_id": {
				Type:        framework.TypeInt,
				Description: "NetBox token id of the seeded admin token, so config/rotate can delete it after reissue. Auto-discovered for v2 tokens if omitted.",
			},
			"token_version": {
				Type:        framework.TypeInt,
				Description: "NetBox token version to request when minting (default 2). Use 1 if the NetBox server has no API_TOKEN_PEPPERS configured.",
				Default:     2,
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM CA certificate that signed the NetBox server's TLS certificate.",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS verification of the NetBox server (not recommended).",
				Default:     false,
			},
			"request_timeout_seconds": {
				Type:        framework.TypeInt,
				Description: "HTTP timeout in seconds for calls to NetBox (default 30).",
				Default:     30,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    "Configure the connection to NetBox and the seeded admin token.",
		HelpDescription: "Configure the URL, TLS settings, and seeded admin token the backend uses to mint NetBox tokens. Roles are configured on roles/<name>.",
	}
}

func pathConfigRotate(b *netboxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "netbox",
			OperationSuffix: "config-rotate",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigRotate},
		},
		HelpSynopsis:    "Reissue the seeded NetBox admin token.",
		HelpDescription: "Mints a fresh admin token for the seeded user with the current token, stores it, and deletes the old token. NetBox has no in-place rotation.",
	}
}

func (b *netboxBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *netboxBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	// The admin token is never returned.
	return &logical.Response{
		Data: map[string]interface{}{
			"netbox_url":              config.NetboxURL,
			"admin_user_id":           config.AdminUserID,
			"admin_token_id":          config.AdminTokenID,
			"token_version":           config.TokenVersion,
			"tls_skip_verify":         config.TLSSkipVerify,
			"request_timeout_seconds": config.RequestTimeoutSeconds,
		},
	}, nil
}

func (b *netboxBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = &netboxConfig{}
	}

	if v, ok := data.GetOk("netbox_url"); ok {
		config.NetboxURL = v.(string)
	}
	if v, ok := data.GetOk("token"); ok {
		config.Token = v.(string)
	}
	if v, ok := data.GetOk("admin_user_id"); ok {
		config.AdminUserID = v.(int)
	}
	if v, ok := data.GetOk("admin_token_id"); ok {
		config.AdminTokenID = v.(int)
	}
	if v, ok := data.GetOk("token_version"); ok {
		config.TokenVersion = v.(int)
	} else if req.Operation == logical.CreateOperation {
		config.TokenVersion = data.Get("token_version").(int)
	}
	if v, ok := data.GetOk("ca_cert"); ok {
		config.CACert = v.(string)
	}
	if v, ok := data.GetOk("tls_skip_verify"); ok {
		config.TLSSkipVerify = v.(bool)
	}
	if v, ok := data.GetOk("request_timeout_seconds"); ok {
		config.RequestTimeoutSeconds = v.(int)
	} else if req.Operation == logical.CreateOperation {
		config.RequestTimeoutSeconds = data.Get("request_timeout_seconds").(int)
	}

	if config.NetboxURL == "" {
		return logical.ErrorResponse("netbox_url is required"), nil
	}
	if config.Token == "" {
		return logical.ErrorResponse("token (admin) is required"), nil
	}
	if config.TokenVersion != 1 && config.TokenVersion != 2 {
		return logical.ErrorResponse("token_version must be 1 or 2"), nil
	}

	return nil, setJSON(ctx, req.Storage, configStoragePath, config)
}

func (b *netboxBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, configStoragePath)
}

func (b *netboxBackend) pathConfigRotate(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}

	// Resolve the ids of the current admin token so we can reissue for the same
	// user and delete the old one. Auto-discover from the v2 key if not stored.
	userID, oldTokenID := config.AdminUserID, config.AdminTokenID
	if (userID == 0 || oldTokenID == 0) && strings.HasPrefix(config.Token, tokenPrefix) {
		if key := adminTokenKey(config.Token); key != "" {
			if id, uid, lerr := client.LookupTokenByKey(ctx, key); lerr == nil {
				if oldTokenID == 0 {
					oldTokenID = id
				}
				if userID == 0 {
					userID = uid
				}
			}
		}
	}
	if userID == 0 {
		return logical.ErrorResponse("admin_user_id is unknown; set it on config to enable rotation"), nil
	}

	minted, err := client.MintToken(ctx, mintRequest{
		UserID:       userID,
		WriteEnabled: true,
		Description:  "vault-managed netbox admin token",
	})
	if err != nil {
		return nil, fmt.Errorf("minting replacement admin token: %w", err)
	}

	config.Token = credentialFor(minted)
	config.AdminUserID = userID
	config.AdminTokenID = minted.ID
	if err := setJSON(ctx, req.Storage, configStoragePath, config); err != nil {
		return nil, fmt.Errorf("persisting rotated admin token: %w", err)
	}

	// Delete the superseded token using the new credential.
	if oldTokenID != 0 && oldTokenID != minted.ID {
		if newClient, cerr := newClient(config); cerr == nil {
			if derr := newClient.DeleteToken(ctx, oldTokenID); derr != nil {
				b.Logger().Warn("netbox: could not delete superseded admin token", "token_id", oldTokenID, "error", derr)
			}
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"admin_user_id":  config.AdminUserID,
			"admin_token_id": config.AdminTokenID,
			"rotated_at":     time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// adminTokenKey extracts the v2 identification key from an "nbt_<key>.<secret>"
// credential, or "" if the shape is not recognised.
func adminTokenKey(credential string) string {
	rest := strings.TrimPrefix(credential, tokenPrefix)
	if key, _, ok := strings.Cut(rest, "."); ok {
		return key
	}
	return ""
}

func getConfig(ctx context.Context, s logical.Storage) (*netboxConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	config := &netboxConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

// setJSON stores a value as a JSON storage entry.
func setJSON(ctx context.Context, s logical.Storage, key string, value interface{}) error {
	entry, err := logical.StorageEntryJSON(key, value)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

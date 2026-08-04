package netbox

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleStoragePrefix = "role/"

// netboxRole mints NetBox tokens for a pre-existing NetBox service user. Each
// read of creds/<name> produces a unique, lease-bound token for NetboxUserID.
type netboxRole struct {
	// NetboxUserID is the id of the NetBox user tokens are minted for.
	NetboxUserID int `json:"netbox_user_id"`
	// NetboxUsername is informational (the resolved user's name), kept for
	// readability of role reads.
	NetboxUsername string `json:"netbox_username"`
	// WriteEnabled controls whether minted tokens permit write operations.
	// Defaults to false so roles are read-only unless explicitly opted in.
	WriteEnabled bool `json:"write_enabled"`
	// Description is applied to each minted token (helps auditing in NetBox).
	Description string        `json:"description"`
	TTL         time.Duration `json:"ttl"`
	MaxTTL      time.Duration `json:"max_ttl"`
}

func pathRole(b *netboxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "netbox",
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
				Required:    true,
			},
			"netbox_user_id": {
				Type:        framework.TypeInt,
				Description: "Id of the pre-existing NetBox service user that minted tokens belong to. Either this or netbox_username is required.",
			},
			"netbox_username": {
				Type:        framework.TypeString,
				Description: "Username of the NetBox service user, resolved to an id at write time. Alternative to netbox_user_id.",
			},
			"write_enabled": {
				Type:        framework.TypeBool,
				Description: "Whether minted tokens permit create/update/delete (default false: read-only tokens).",
				Default:     false,
			},
			"description": {
				Type:        framework.TypeString,
				Description: "Description applied to each minted NetBox token.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL for tokens minted from this role. The minted token's NetBox expiry is aligned to the lease.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL for tokens minted from this role.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
		ExistenceCheck:  b.pathRoleExistenceCheck,
		HelpSynopsis:    "Manage roles that mint NetBox tokens for a service user.",
		HelpDescription: "Each read of creds/<name> mints a unique, lease-bound NetBox token for the role's NetBox user.",
	}
}

func pathRolesList(b *netboxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "netbox",
			OperationSuffix: "roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
		},
		HelpSynopsis:    "List roles.",
		HelpDescription: "List the token-minting roles configured on this backend.",
	}
}

func (b *netboxBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *netboxBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"netbox_user_id":  role.NetboxUserID,
			"netbox_username": role.NetboxUsername,
			"write_enabled":   role.WriteEnabled,
			"description":     role.Description,
			"ttl":             int64(role.TTL.Seconds()),
			"max_ttl":         int64(role.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *netboxBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &netboxRole{}
	}

	if v, ok := data.GetOk("netbox_user_id"); ok {
		role.NetboxUserID = v.(int)
	}
	if v, ok := data.GetOk("netbox_username"); ok {
		role.NetboxUsername = v.(string)
	}
	if v, ok := data.GetOk("write_enabled"); ok {
		role.WriteEnabled = v.(bool)
	}
	if v, ok := data.GetOk("description"); ok {
		role.Description = v.(string)
	}
	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}

	// Resolve a username to an id if no id was given directly.
	if role.NetboxUserID == 0 && role.NetboxUsername != "" {
		client, cerr := b.client(ctx, req.Storage)
		if cerr != nil {
			return nil, cerr
		}
		id, rerr := client.ResolveUserID(ctx, role.NetboxUsername)
		if rerr != nil {
			return logical.ErrorResponse("resolving netbox_username %q: %s", role.NetboxUsername, rerr), nil
		}
		role.NetboxUserID = id
	}

	if role.NetboxUserID == 0 {
		return logical.ErrorResponse("netbox_user_id or netbox_username is required"), nil
	}
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl must not exceed max_ttl"), nil
	}

	return nil, setJSON(ctx, req.Storage, roleStoragePrefix+name, role)
}

func (b *netboxBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, roleStoragePrefix+data.Get("name").(string))
}

func (b *netboxBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *netboxBackend) getRole(ctx context.Context, s logical.Storage, name string) (*netboxRole, error) {
	if name == "" {
		return nil, errors.New("missing role name")
	}
	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &netboxRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

package netbox

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *netboxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "netbox",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to mint a token for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    "Mint a NetBox token from a role.",
		HelpDescription: "Reading this path mints a new, lease-bound NetBox API token for the role's user with its NetBox expiry aligned to the lease; the token is deleted from NetBox when the lease is revoked.",
	}
}

func (b *netboxBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	client, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	ttl, maxTTL := b.resolveTTLs(role.TTL, role.MaxTTL)

	description := role.Description
	if description == "" {
		description = fmt.Sprintf("vault dynamic token (role %q)", roleName)
	}

	minted, err := client.MintToken(ctx, mintRequest{
		UserID:       role.NetboxUserID,
		WriteEnabled: role.WriteEnabled,
		Description:  description,
		Expires:      time.Now().Add(ttl),
	})
	if err != nil {
		return nil, fmt.Errorf("minting netbox token: %w", err)
	}

	credential := credentialFor(minted)

	internal := map[string]interface{}{
		"token_id": minted.ID,
	}
	external := map[string]interface{}{
		"token":          credential,
		"token_scheme":   schemeFor(minted.Version),
		"authorization":  schemeFor(minted.Version) + " " + credential,
		"key":            minted.Key,
		"version":        minted.Version,
		"netbox_user_id": role.NetboxUserID,
		"write_enabled":  role.WriteEnabled,
		"expires":        minted.Expires,
	}

	resp := b.Secret(netboxTokenType).Response(external, internal)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	resp.Secret.Renewable = true
	return resp, nil
}

// schemeFor returns the HTTP Authorization scheme keyword for a token version.
func schemeFor(version int) string {
	if version == 2 {
		return "Bearer"
	}
	return "Token"
}

// resolveTTLs clamps a role's TTL/MaxTTL against the mount and system limits.
func (b *netboxBackend) resolveTTLs(roleTTL, roleMaxTTL time.Duration) (ttl, maxTTL time.Duration) {
	sysMaxTTL := b.System().MaxLeaseTTL()
	maxTTL = roleMaxTTL
	if maxTTL <= 0 || maxTTL > sysMaxTTL {
		maxTTL = sysMaxTTL
	}
	ttl = roleTTL
	if ttl <= 0 {
		ttl = b.System().DefaultLeaseTTL()
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl, maxTTL
}

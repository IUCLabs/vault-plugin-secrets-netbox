package netbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const netboxTokenType = "netbox_token"

// expiryBuffer keeps the NetBox token's expiry slightly ahead of the Vault lease
// so it never lapses a moment before the lease it is bound to.
const expiryBuffer = time.Minute

func (b *netboxBackend) netboxTokenSecret() *framework.Secret {
	return &framework.Secret{
		Type: netboxTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The usable NetBox token credential (v2: nbt_<key>.<secret>; v1: bare value).",
			},
			"authorization": {
				Type:        framework.TypeString,
				Description: "The full Authorization header value for the token.",
			},
		},
		Revoke: b.secretRevoke,
		Renew:  b.secretRenew,
	}
}

// secretRevoke deletes the minted NetBox token via the API, using the seeded
// admin token.
func (b *netboxBackend) secretRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tokenID, err := internalInt(req.Secret.InternalData, "token_id")
	if err != nil {
		return nil, err
	}

	client, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if err := client.DeleteToken(ctx, tokenID); err != nil {
		return nil, fmt.Errorf("revoking netbox token %d: %w", tokenID, err)
	}
	return nil, nil
}

// secretRenew extends the Vault lease and pushes the NetBox token's expiry
// forward to match, since NetBox permits updating a token's expires.
func (b *netboxBackend) secretRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tokenID, err := internalInt(req.Secret.InternalData, "token_id")
	if err != nil {
		return nil, err
	}

	if req.Secret.TTL > 0 {
		client, cerr := b.client(ctx, req.Storage)
		if cerr != nil {
			return nil, cerr
		}
		newExpiry := time.Now().Add(req.Secret.TTL + expiryBuffer)
		if err := client.ExtendToken(ctx, tokenID, newExpiry); err != nil {
			return nil, fmt.Errorf("extending netbox token %d expiry: %w", tokenID, err)
		}
	}

	return &logical.Response{Secret: req.Secret}, nil
}

// internalInt reads an integer from a secret's internal data, tolerating the
// float64/json.Number shapes JSON round-tripping produces.
func internalInt(data map[string]interface{}, key string) (int, error) {
	raw, ok := data[key]
	if !ok {
		return 0, fmt.Errorf("secret is missing internal %s data", key)
	}
	switch n := raw.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, fmt.Errorf("secret internal %s data is not an integer: %w", key, err)
		}
		return int(i), nil
	default:
		return 0, fmt.Errorf("secret internal %s data has unexpected type %T", key, raw)
	}
}

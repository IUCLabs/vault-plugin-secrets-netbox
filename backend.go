// Package netbox implements a Vault / OpenBao secrets engine that mints NetBox
// API tokens through NetBox's REST API (/api/users/tokens/).
//
// The engine is seeded with a single long-lived NetBox admin token (config).
// Unlike some upstreams, NetBox lets an admin token create tokens for *other*
// users, so one seeded credential is enough: a role names a pre-existing NetBox
// service user and the token options (ttl/max_ttl, write_enabled), and each read
// of creds/<role> mints a fresh, lease-bound token for that user whose NetBox
// `expires` is aligned to the Vault lease. Revoking the lease deletes the token
// from NetBox; renewing it PATCHes `expires` forward.
//
// The seeded admin token can be reissued via config/rotate (NetBox has no
// in-place rotate; the engine mints a replacement for the admin user and deletes
// the old one).
package netbox

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// errBackendNotConfigured is returned when a credential is requested before the
// NetBox connection has been configured.
var errBackendNotConfigured = errors.New("netbox backend not configured; write config first")

type netboxBackend struct {
	*framework.Backend

	lock sync.RWMutex
}

// Factory returns a configured NetBox secrets backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *netboxBackend {
	b := &netboxBackend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathConfigRotate(b),
				pathRole(b),
				pathRolesList(b),
				pathCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.netboxTokenSecret(),
		},
	}

	return b
}

// client builds a NetBox client from the stored config, authenticated with the
// seeded admin token.
func (b *netboxBackend) client(ctx context.Context, s logical.Storage) (*netboxClient, error) {
	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}
	return newClient(config)
}

const backendHelp = `
The netbox secrets engine mints NetBox API tokens via /api/users/tokens/.

Seed a single NetBox admin token in config; roles name a pre-existing NetBox
service user plus token options (ttl/max_ttl, write_enabled). Reading
creds/<role> mints a short-lived token for that user with its NetBox expiry
aligned to the Vault lease, deleted from NetBox on revoke. config/rotate
reissues the seeded admin token.
`

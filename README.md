# vault-plugin-secrets-netbox

A Vault / OpenBao secrets engine that mints **NetBox API tokens** through
NetBox's REST API (`/api/users/tokens/`).

## Why

Long-lived NetBox tokens handed to CI and to Puppet fact collectors are hard to
rotate and easy to leak. This engine issues **short-lived, per-user tokens on
demand**, each bound to a Vault lease: the token's NetBox `expires` is aligned to
the lease, the lease renewal pushes `expires` forward, and revoking the lease
deletes the token from NetBox.

A single seeded **admin token** authenticates the engine. NetBox lets an admin
token create tokens for *other* users (with `add_token` + `grant_token`), so one
credential is enough — a role just names a pre-existing NetBox service user.

## NetBox token model (4.6+)

NetBox 4.6 issues **v2 tokens** by default: only an HMAC digest is stored, and
the plaintext is returned **once**, at creation. A v2 credential authenticates as
`Authorization: Bearer nbt_<key>.<secret>`. Legacy **v1 tokens** (bare 40-char
value) authenticate as `Authorization: Token <value>`.

- The engine returns both the raw `token` credential and a ready-to-use
  `authorization` header value on each mint.
- v2 tokens require `API_TOKEN_PEPPERS` to be configured on the NetBox server. If
  yours is not, set `token_version=1` on `config` to mint v1 tokens (drop-in for
  older NetBox API clients that only send the `Token` scheme).

## Paths

| Path | Description |
|------|-------------|
| `config` | NetBox URL, TLS settings, seeded admin `token`, `token_version`, optional `admin_user_id`/`admin_token_id`. |
| `config/rotate` | Reissue the seeded admin token (mint a replacement for the admin user, delete the old). |
| `roles/<name>` | Mint policy: `netbox_user_id` (or `netbox_username`), `write_enabled` (default false), `ttl`, `max_ttl`, `description`. |
| `creds/<role>` | Read to mint a short-lived, lease-bound token. |

## Usage

```sh
vault secrets enable -path=netbox vault-plugin-secrets-netbox

vault write netbox/config \
  netbox_url=https://netbox.example.com \
  token="nbt_ab12cd34ef56.XXXXXXXX" \
  ca_cert=@netbox-ca.pem

# A read-only role for a NetBox service user (write_enabled defaults to false).
vault write netbox/roles/puppet-facts netbox_username=svc-puppet-facts ttl=1h max_ttl=8h

# A write-enabled role.
vault write netbox/roles/terraform-ipam netbox_username=svc-terraform-ipam \
  write_enabled=true ttl=30m max_ttl=4h

# Mint one.
vault read netbox/creds/puppet-facts
# -> token, authorization ("Bearer nbt_<key>.<secret>"), expires, ...
```

Each role points at its **own** pre-existing NetBox service user (e.g.
`svc-terraform-ipam`, `svc-puppet-facts`), so a minted token carries exactly that
user's NetBox permissions. `write_enabled=false` additionally forbids
create/update/delete regardless of the user's rights.

## Development

```sh
make build      # build the plugin binary into ./dist
make test       # unit tests (httptest mock NetBox)
make e2e        # full lifecycle vs mock NetBox on Vault + OpenBao (Docker)
make rpm        # build Vault + OpenBao RPMs via nfpm
```

Releases are tag-driven (`make patch|minor|major`): a Woodpecker pipeline builds
the RPMs and uploads them to the internal artifactapi yum repo.

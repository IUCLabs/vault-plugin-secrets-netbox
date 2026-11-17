# vault-plugin-secrets-netbox

A [HashiCorp Vault](https://www.vaultproject.io/) / [OpenBao](https://openbao.org/)
secrets engine that issues short-lived [NetBox](https://netboxlabs.com/oss/netbox/)
API tokens.

The engine holds one NetBox admin token. Each role names an existing NetBox
service user; reading `creds/<role>` creates a new token for that user whose
NetBox expiry follows the Vault lease. Renewing the lease extends the token,
revoking it deletes the token from NetBox.

To manage the engine's backends and roles with Terraform or OpenTofu, use
[terraform-provider-vault-secrets-netbox](https://github.com/IUCLabs/terraform-provider-vault-secrets-netbox).

## Requirements

- Vault or OpenBao; tested against Vault 1.18 and the latest OpenBao release
- NetBox with the `/api/users/tokens/` API. v2 tokens (the default) need
  NetBox 4.6+ with `API_TOKEN_PEPPERS` set; otherwise use `token_version=1`.
- A NetBox admin token with the `add_token` and `grant_token` permissions
- Go 1.25+ to build from source

## Installation

Build the binary (or download one from the
[releases page](https://github.com/IUCLabs/vault-plugin-secrets-netbox/releases)):

```sh
go install github.com/IUCLabs/vault-plugin-secrets-netbox/cmd/vault-plugin-secrets-netbox@latest
```

Copy it into the directory set as `plugin_directory` in the server config, register it in the plugin catalog
and enable the secrets engine. With OpenBao, use `bao` in place of `vault`.

```sh
SHA256=$(sha256sum <plugin_directory>/vault-plugin-secrets-netbox | cut -d' ' -f1)

vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-netbox

vault secrets enable -path=netbox vault-plugin-secrets-netbox
```

## Configuration

Point the backend at NetBox and give it the admin token:

```sh
vault write netbox/config \
  netbox_url=https://netbox.example.com \
  token="nbt_<key>.<secret>" \
  ca_cert=@netbox-ca.pem
```

The admin token is write-only. Reissue it at any time with:

```sh
vault write -f netbox/config/rotate
```

## Usage

Create a role per NetBox service user. Tokens are read-only unless
`write_enabled=true`:

```sh
vault write netbox/roles/inventory-reader \
  netbox_username=svc-inventory ttl=1h max_ttl=8h

vault write netbox/roles/ipam-writer \
  netbox_username=svc-ipam write_enabled=true ttl=30m max_ttl=4h
```

Request a token:

```sh
$ vault read netbox/creds/inventory-reader
Key                Value
---                -----
lease_id           netbox/creds/inventory-reader/AbCd...
lease_duration     1h
lease_renewable    true
authorization      Bearer nbt_k3y.s3cr3t
token              nbt_k3y.s3cr3t
token_scheme       Bearer
...
```

Send `authorization` as the `Authorization` header to the NetBox API. A token
carries the NetBox permissions of its role's user.

## Documentation

Full path reference, with every parameter:

- [config](docs/config.md): `config`, `config/rotate`
- [roles](docs/roles.md): `roles/<name>`, `roles/`
- [creds](docs/creds.md): `creds/<name>`, lease renew and revoke

## Development

```sh
make build   # build into ./dist
make test    # unit tests
make e2e     # full lifecycle against Vault and OpenBao in Docker
```

## License

[MIT](LICENSE)

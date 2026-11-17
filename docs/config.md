# Config

The `config` path holds the NetBox connection and the admin token the engine
uses to create, extend and delete tokens. Paths below assume the engine is
mounted at `netbox/`.

## Write config

| Method | Path |
|--------|------|
| `POST` | `/netbox/config` |

### Parameters

- `netbox_url` `(string: <required on first write>)` - Base URL of the NetBox server, e.g.
  `https://netbox.example.com`.
- `token` `(string: <required on first write>)` - NetBox admin API token. For v2 tokens this is
  the full `nbt_<key>.<secret>` string, for v1 the bare 40-character value. It is
  never returned on read.
- `token_version` `(int: 2)` - NetBox token version to create. Use `1` when the
  NetBox server has no `API_TOKEN_PEPPERS` configured.
- `admin_user_id` `(int: 0)` - NetBox user id that owns the admin token. Needed
  by `config/rotate`; discovered automatically for v2 tokens.
- `admin_token_id` `(int: 0)` - NetBox id of the admin token, so `config/rotate`
  can delete it. Discovered automatically for v2 tokens.
- `ca_cert` `(string: "")` - PEM CA certificate that signed NetBox's TLS
  certificate.
- `tls_skip_verify` `(bool: false)` - Skip TLS verification of NetBox. Not
  recommended.
- `request_timeout_seconds` `(int: 30)` - HTTP timeout for calls to NetBox.

On update, only the parameters given are changed.

### Example

```sh
vault write netbox/config \
  netbox_url=https://netbox.example.com \
  token="nbt_<key>.<secret>" \
  ca_cert=@netbox-ca.pem
```

## Read config

| Method | Path |
|--------|------|
| `GET`  | `/netbox/config` |

Returns every parameter except `token` and `ca_cert`.

```sh
$ vault read netbox/config
Key                        Value
---                        -----
admin_token_id             12
admin_user_id              1
netbox_url                 https://netbox.example.com
request_timeout_seconds    30
tls_skip_verify            false
token_version              2
```

## Delete config

| Method   | Path |
|----------|------|
| `DELETE` | `/netbox/config` |

```sh
vault delete netbox/config
```

## Rotate the admin token

| Method | Path |
|--------|------|
| `POST` | `/netbox/config/rotate` |

NetBox cannot rotate a token in place, so the engine creates a new
write-enabled token for the admin user, stores it, then deletes the old one.
For v1 tokens, set `admin_user_id` on `config` first, and `admin_token_id`
too or the old token is not deleted after rotation.

```sh
$ vault write -f netbox/config/rotate
Key               Value
---               -----
admin_token_id    13
admin_user_id     1
rotated_at        2026-01-01T00:00:00Z
```

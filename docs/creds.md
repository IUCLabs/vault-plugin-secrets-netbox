# Creds

Reading `creds/<name>` creates a new NetBox token for the role's user and
returns it under a Vault lease. Paths below assume the engine is mounted at
`netbox/`.

## Generate a token

| Method        | Path |
|---------------|------|
| `GET` / `POST` | `/netbox/creds/:name` |

### Parameters

- `name` `(string: <required>)` - Name of the role. Part of the URL.

### Response fields

- `token` - The credential: `nbt_<key>.<secret>` for v2 tokens, the bare value
  for v1.
- `token_scheme` - `Bearer` for v2 tokens, `Token` for v1.
- `authorization` - Ready-made `Authorization` header value
  (`<token_scheme> <token>`).
- `key` - The token key (v2 tokens only).
- `version` - NetBox token version.
- `netbox_user_id` - NetBox user the token belongs to.
- `write_enabled` - Whether the token may write.
- `expires` - NetBox expiry timestamp of the token.

### Example

```sh
$ vault read netbox/creds/inventory-reader
Key                Value
---                -----
lease_id           netbox/creds/inventory-reader/AbCd...
lease_duration     1h
lease_renewable    true
authorization      Bearer nbt_k3y.s3cr3t
expires            2026-01-01T01:00:00Z
key                k3y
netbox_user_id     43
token              nbt_k3y.s3cr3t
token_scheme       Bearer
version            2
write_enabled      false
```

```sh
TOKEN=$(vault read -field=authorization netbox/creds/inventory-reader)
curl -H "Authorization: $TOKEN" https://netbox.example.com/api/dcim/sites/
```

## Renew

Renewing the lease moves the NetBox token's expiry forward to match (plus one
minute of headroom), up to the role's `max_ttl`.

```sh
vault lease renew netbox/creds/inventory-reader/AbCd...
```

## Revoke

Revoking the lease deletes the token from NetBox.

```sh
vault lease revoke netbox/creds/inventory-reader/AbCd...

# Revoke every token issued from a role
vault lease revoke -prefix netbox/creds/inventory-reader
```

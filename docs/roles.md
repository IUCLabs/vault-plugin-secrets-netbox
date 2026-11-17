# Roles

A role names an existing NetBox service user and sets the options for tokens
created from it. A token carries the NetBox permissions of that user;
`write_enabled=false` additionally blocks create/update/delete. Paths below
assume the engine is mounted at `netbox/`.

## Create or update a role

| Method | Path |
|--------|------|
| `POST` | `/netbox/roles/:name` |

### Parameters

- `name` `(string: <required>)` - Name of the role. Part of the URL.
- `netbox_user_id` `(int: 0)` - Id of the NetBox user tokens are created for.
  Set this or `netbox_username`.
- `netbox_username` `(string: "")` - Username of the NetBox user. Resolved to an
  id when the role is written, so `config` must exist first.
- `write_enabled` `(bool: false)` - Whether tokens may create, update and delete
  objects.
- `description` `(string: "")` - Description set on each NetBox token. Defaults
  to `vault dynamic token (role "<name>")`.
- `ttl` `(duration: "")` - Default lease TTL. Defaults to the mount's default
  lease TTL. The NetBox token expiry follows the lease.
- `max_ttl` `(duration: "")` - Maximum lease TTL. Defaults to the mount's
  maximum lease TTL. `ttl` must not exceed it.

On update, only the parameters given are changed.

### Example

```sh
vault write netbox/roles/inventory-reader \
  netbox_username=svc-inventory \
  ttl=1h \
  max_ttl=8h

vault write netbox/roles/ipam-writer \
  netbox_user_id=42 \
  write_enabled=true \
  description="IPAM automation" \
  ttl=30m \
  max_ttl=4h
```

## Read a role

| Method | Path |
|--------|------|
| `GET`  | `/netbox/roles/:name` |

```sh
$ vault read netbox/roles/inventory-reader
Key                Value
---                -----
description
max_ttl            28800
netbox_user_id     43
netbox_username    svc-inventory
ttl                3600
write_enabled      false
```

`ttl` and `max_ttl` are returned in seconds.

## List roles

| Method | Path |
|--------|------|
| `LIST` | `/netbox/roles` |

```sh
$ vault list netbox/roles
Keys
----
inventory-reader
ipam-writer
```

## Delete a role

| Method   | Path |
|----------|------|
| `DELETE` | `/netbox/roles/:name` |

Deleting a role does not revoke tokens already created from it.

```sh
vault delete netbox/roles/ipam-writer
```

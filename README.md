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

Release assets download through artifactapi's GitHub proxy, which serves
`https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-netbox/releases/download/<tag>/<file>`.
Each method below ends with `SHA256` set for [registration](#register-and-enable).
With OpenBao, use `bao` in place of `vault`.

```sh
TAG=vX.Y.Z  # the release to install
V=${TAG#v}
BASE=https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-netbox/releases/download/$TAG
```

### RPM

Install the Vault RPM or the OpenBao RPM, not both. Set the server's
`plugin_directory` to the directory the RPM installs into.

Vault: installs `/usr/libexec/vault-plugins/vault-plugin-secrets-netbox`.

```sh
dnf install vault-plugin-secrets-netbox  # from a yum repo carrying it, or from the release:
dnf install "$BASE/vault-plugin-secrets-netbox-$V-1.x86_64.rpm"

SHA256=$(sha256sum /usr/libexec/vault-plugins/vault-plugin-secrets-netbox | cut -d' ' -f1)
```

OpenBao: installs `/usr/libexec/openbao-plugins/vault-plugin-secrets-netbox`.

```sh
dnf install openbao-plugin-secrets-netbox  # from a yum repo carrying it, or from the release:
dnf install "$BASE/openbao-plugin-secrets-netbox-$V-1.x86_64.rpm"

SHA256=$(sha256sum /usr/libexec/openbao-plugins/vault-plugin-secrets-netbox | cut -d' ' -f1)
```

### Released binary

`vault-plugin-secrets-netbox_<version>_SHA256SUMS` lists the binary and the RPMs.

```sh
curl -fLO "$BASE/vault-plugin-secrets-netbox_${V}_linux_amd64"
curl -fLO "$BASE/vault-plugin-secrets-netbox_${V}_SHA256SUMS"
sha256sum --check --ignore-missing "vault-plugin-secrets-netbox_${V}_SHA256SUMS"

install -m 0755 "vault-plugin-secrets-netbox_${V}_linux_amd64" <plugin_directory>/vault-plugin-secrets-netbox
SHA256=$(sha256sum <plugin_directory>/vault-plugin-secrets-netbox | cut -d' ' -f1)
```

### Kubernetes image volume

`ghcr.io/iuclabs/vault-plugin-secrets-netbox:<tag>` is a `FROM scratch` image holding only
`/vault-plugin-secrets-netbox`. Mount it read-only into the Vault/OpenBao container with an
[image volume](https://kubernetes.io/docs/concepts/storage/volumes/#image):
Image volumes are beta from Kubernetes 1.33 but off by default (enable the
`ImageVolume` feature gate), on by default from 1.35, and GA in 1.36. Vault and OpenBao only run a binary that sits directly in
`plugin_directory`, not in a subdirectory, so mount the file itself with
`subPath`, which on image volumes needs 1.33+.

```yaml
spec:
  containers:
    - name: vault
      volumeMounts:
        - name: plugin-netbox
          mountPath: /vault/plugins/vault-plugin-secrets-netbox  # <plugin_directory>/vault-plugin-secrets-netbox
          subPath: vault-plugin-secrets-netbox
          readOnly: true
  volumes:
    - name: plugin-netbox
      image:
        reference: ghcr.io/iuclabs/vault-plugin-secrets-netbox:vX.Y.Z
        pullPolicy: IfNotPresent
```

The image holds the released binary, so its sha256 is the `linux_amd64` line
of `SHA256SUMS`:

```sh
SHA256=$(curl -fsSL "$BASE/vault-plugin-secrets-netbox_${V}_SHA256SUMS" | awk '/_linux_amd64$/ {print $1}')
```

### From source

```sh
make build  # writes ./dist/vault-plugin-secrets-netbox
```

Copy it into `plugin_directory` and take `SHA256` from `sha256sum` as above.

### Register and enable

```sh
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-netbox
vault secrets enable -path=netbox vault-plugin-secrets-netbox
```

After replacing the binary, register the new sha256 and reload the plugin:

```sh
vault write sys/plugins/reload/backend plugin=vault-plugin-secrets-netbox
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

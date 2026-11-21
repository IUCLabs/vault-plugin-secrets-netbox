FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/vault-plugin-secrets-netbox /vault-plugin-secrets-netbox
ENTRYPOINT ["/vault-plugin-secrets-netbox"]

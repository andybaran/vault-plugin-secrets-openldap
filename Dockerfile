# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: MPL-2.0

# Layer a pre-compiled vault-plugin-secrets-openldap binary into the
# official HashiCorp Vault image.
#
# Build the plugin first (cross-compile for the target platform):
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
#       -o vault-plugin-secrets-openldap ./cmd/vault-plugin-secrets-openldap
#
# Then build the image:
#   docker build --platform linux/amd64 -t <tag> .

FROM hashicorp/vault:latest

COPY --chown=vault:vault \
    vault-plugin-secrets-openldap \
    /vault/plugins/vault-plugin-secrets-openldap

RUN chmod +x /vault/plugins/vault-plugin-secrets-openldap

# Tell Vault where to find external plugins.
ENV VAULT_PLUGIN_DIR=/vault/plugins

#WIP

Certificate monitoring process that :
- checks for certificate expiration
- generates missing certificates based on configuration
- executes a command when certificate is renewed (ex: reload a service like
  Apache)

The certificate backend used is Hashicorp Vault.

# Testing
Basic Vault configuration example.

## Vault Development Setup

Start (dev mode)
```bash
vault server -dev
```

Setup
```bash
export VAULT_TOKEN=
export VAULT_ADDR='http://127.0.0.1:8200'

vault mount pki
vault mount-tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal common_name=webserver ttl=87600h
vault write pki/config/urls issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
vault write pki/roles/webservers allowed_domains=mydomain.local allow_subdomains="true" max_ttl="72h" client_flag=false key_usage=DigitalSignature,KeyEncipherment
```

Generate a certificate
```bash
vault write pki/issue/webservers common_name=s01-test-app-test.mydomain.local alt_names=n1-s01-test-app-test.mydomain.local
```

Exemple: issue certificate using curl

/tmp/payload.json:

> {
>   "common_name": "test.mydomain.local",
>   "alt_names": "n1-test.mydomain.local"
> }

```bash
curl \
    --header "X-Vault-Token: ${VAULT_TOKEN}" \
    --request POST \
    --data @/tmp/payload.json \
    http://localhost:8200/v1/pki/issue/webservers
```

## Configure a Vault Role
Enable approle backend
```bash
vault auth-enable approle
```

Periodic token, no expiration
```bash
vault write auth/approle/role/testrole period=10m policies=certmon
```

Retreive role_id
```bash
vault read auth/approle/role/testrole/role-id
```

Generate secret_id
```bash
vault write -f auth/approle/role/testrole/secret-id
```

# TODO:
- Testing
- Refactoring to support other backends (CFSSL?)


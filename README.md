[![Build Status](https://travis-ci.org/vdesjardins/cert-monitor.svg?branch=master)](https://travis-ci.org/vdesjardins/cert-monitor)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fvdesjardins%2Fcert-monitor.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fvdesjardins%2Fcert-monitor?ref=badge_shield)

#WIP

Certificate monitoring process that :
- checks for certificate expiration
- generates missing certificates based on configuration
- executes a command when certificate is renewed (ex: reload a service like
  Apache)

The certificate backend used is Hashicorp Vault.

# Cert-Monitor Configuration
Main configuration example:
```yaml
checkInterval: 60m
downloadedCertPath: /var/cache/cert-monitor
includePaths:
- /etc/cert-monitor.d/*.yml
vault:
    baseUrl: http://127.0.0.1:8200
    certPath: /v1/pki/issue/webservers
    loginPath: /v1/auth/approle/login
    roleId: <token elided>
    secretId: <token elided>
```

Certificate check configuration example:
```yaml
commonName: n1-test.mydomain.com
alternateNames: [ test.mydomain.com ]
reloadCommand: /usr/sbin/apachectl graceful
user: nobody
group: nobody
ttl: 1344h
renewTtl: 672h
output:
  file:
    type: bundle
    name: /etc/httpd/conf.d/n1-test.mydomain.net.pem
    perm: 0600
  items:
    - certificate
    - chain
    - privateKey
```

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



## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fvdesjardins%2Fcert-monitor.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fvdesjardins%2Fcert-monitor?ref=badge_large)
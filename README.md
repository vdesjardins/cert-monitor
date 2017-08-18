#WIP

Certificate monitoring daemon that :
- checks for certificate expiration
- generate missing certificates based on configuration
- execute a command when certificate is renewed (ex: reload a service like
  Apache)

The certificate backend used is Hashicorp Vault.

TODO:
- Daemonize it / startup scripts
- Testing
- Refactoring to support other backends (CFSSL?)
- Document it


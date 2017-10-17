#!/bin/bash

set -e

temp_dir=$(mktemp -d)

vault_output_file=${temp_dir}/vault-test-server.log

vault server -dev >${vault_output_file} 2>&1 &
vault_server_pid=$!

function exit_vault_server {
    kill $vault_server_pid >/dev/null 2>&1
    rm -rf ${temp_dir}
}

trap exit_vault_server EXIT

sleep 1

{
    export VAULT_ADDR='http://127.0.0.1:8200'
    export VAULT_TOKEN=$(grep 'Root Token: ' ${vault_output_file} | perl -pe 's/^Root Token:\s(.+)$/\1/g')


    vault mount -path=/pki/web/servers/1 pki
    vault mount-tune -max-lease-ttl=87600h /pki/web/servers/1
    vault write pki/web/servers/1/root/generate/internal common_name=webserver ttl=87600h
    vault write pki/web/servers/1/config/urls issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
    vault write pki/web/servers/1/roles/webservers allowed_domains=domaintest.net allow_subdomains="true" max_ttl="1344h" client_flag=false key_usage=DigitalSignature,KeyEncipherment\n

    cat <<-EOT | vault policy-write cert-monitor -
path "/pki/web/servers/1/issue/webservers" {
  capabilities = [ "create", "update" ]
}
EOT

    vault auth-enable approle

    vault write auth/approle/role/cert-monitor period=10m policies=cert-monitor

    role_id=$(vault read -field=role_id auth/approle/role/cert-monitor/role-id)
    secret_id=$(vault write -field=secret_id -f auth/approle/role/cert-monitor/secret-id)

    mkdir ${temp_dir}/{cfg,tmp,certs}

    # create main configuration file
    cat <<-EOT > ${temp_dir}/config.yml
vault:
  roleId: ${role_id}
  secretId: ${secret_id}
  baseUrl: http://127.0.0.1:8200
  loginPath: /v1/auth/approle/login
  certPath: /v1/pki/web/servers/1/issue/webservers

includePaths:
  - ${temp_dir}/cfg/*.yml
downloadedCertPath: ${temp_dir}/tmp
checkInterval: 5m
EOT

    # create a certificate configuration file
    cat <<-EOT > ${temp_dir}/cfg/cert.yml
commonName: test.domaintest.net
alternateNames: [ n1-test.domaintest.net ]
ttl: 5m
renewTtl: 2m
output:
  file:
    type: bundle
    name: ${temp_dir}/certs/test.mydomain.net.pem
    perm: 0600
  items:
    - certificate
    - chain
    - privateKey
EOT

echo "***************************************"
echo "* Temp Dir        : ${temp_dir}"
echo "* Cfg Dir         : ${temp_dir}/cfg"
echo "* Cache Dir       : ${temp_dir}/tmp"
echo "* Certs Dir       : ${temp_dir}/certs"
echo "* Main Config File: ${temp_dir/}/config.yml"
echo "*"
echo "* Vault:"
echo "*   role_id       : ${role_id}"
echo "*   secret_id     : ${secret_id}"
echo "*"
echo "* Example:"
echo "* ./cert-monitor -config=${temp_dir}/config.yml -onetime"
echo "*"
echo "***************************************"
} 2>&1 | sed "s/^/[init-script] /"

tail -n 100 -f ${vault_output_file}


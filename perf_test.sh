#! /bin/bash
set -euo pipefail


banner() {
    echo -e "\033[0;32m"$1"\033[0m"
}

cleanup() {
    ssh -A cortana.corp.yahoo.com  sudo rm -rf /tmp/ghz || true
    ssh -A cortana.corp.yahoo.com  sudo rm -rf proto googleapis json crypki Dockerfile config log || true
    ssh -A cortana.corp.yahoo.com  sudo docker rm -f udpate-crypki || true
    # ssh -A cortana.corp.yahoo.com  sudo chef-client
}

build_performance_binary() {
  banner "Building performance test binary"
  ssh cortana.corp.yahoo.com  mkdir -p /tmp/ghz
  ssh cortana.corp.yahoo.com  wget https://github.com/bojand/ghz/releases/download/v0.49.0/ghz_0.49.0_Linux_x86_64.tar.gz -P /tmp/
  ssh cortana.corp.yahoo.com  tar -xzf /tmp/ghz_0.49.0_Linux_x86_64.tar.gz -C /tmp/ghz
}

prepare_proto_files() {
    ssh -A cortana.corp.yahoo.com  sudo rm -rf proto googleapis || true

    scp -r ${GOPATH}/pkg/mod/git.ouroath.com/mirror-github/yahoo--crypki\@v1.1.9/proto cortana.corp.yahoo.com:proto
    scp -r ${GOPATH}/pkg/mod/git.ouroath.com/mirror-github/grpc-ecosystem--grpc-gateway\@v1.11.3/third_party/googleapis cortana.corp.yahoo.com:googleapis
}

prepare_json_files() {
    ssh -A cortana.corp.yahoo.com  sudo rm -rf json || true

    mkdir -p json
    cat <<EOF > json/GetUserSSHCertificateSigningKey.json
{
    "identifier":"ssh-user-key"
}
EOF
    cat <<EOF > json/PostUserSSHCertificate.json
{
    "key_meta":{
        "identifier":"ssh-user-key"
    },
    "key_id": "prins=foo, crTime=20180929T134536, host=, reqU=bar, reqIP=baz, transID=deadbeef, isHWKey=true, touchPolicy=3, isFirefighter=false, isHeadless=false. YahooSSHCA",
    "principals":["alice"],
    "public_key":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBD/qJM9Q2KOuAxTOkZecRLSrvBrwCJJiVZRZHy45s/qyUuXLHpcB18AyEt+VmNBjJLlG2oXrdgsI7luZLin1oA=",
    "validity":43200
}'
EOF
    scp -r json cortana.corp.yahoo.com:json
}

prepare_new_crypki() {
    git clean -df
    git reset --hard HEAD
    git checkout master
    git branch -D SSHCA-1756 || true
    git fetch git@git.ouroath.com:pochengp/sshca master:SSHCA-1756
    git checkout SSHCA-1756

    docker run --rm -v $(pwd):/sshca -v ~/:/home/screwdrv --workdir /sshca docker.ouroath.com:4443/go/rhel7 go mod tidy
    docker run --rm -v $(pwd):/sshca -v ~/:/home/screwdrv --workdir /sshca docker.ouroath.com:4443/go/rhel7 go build -o crypki.bin ./crypki/cmd/crypki/main.go
    ssh -A cortana.corp.yahoo.com  sudo rm -rf crypki.bin || true
    scp crypki.bin cortana.corp.yahoo.com:crypki

    cat << EOF > certsignd_config.json
    {
"TLSServerName": "cortana.corp.yahoo.com",
"TLSServerCertPath": "/opt/sshca/CSD/tls_server.crt",
"TLSServerKeyPath": "/opt/sshca/CSD/tls_server.key",
"TLSCACertPath": "/opt/sshca/CSD/tls_ca_2.crt",
"TLSClientAuthMode": 4,
"TLSPort": "6443",
"Keys": [
    {"Identifier": "ssh-user-key", "KeyLabel": "user_ssh", "SlotNumber": 2, "UserPinPath" : "/dev/shm/sshca/slot2_pwd.txt"},
    {"Identifier": "blob-sign-key", "KeyLabel": "rpm_signing_201906", "SlotNumber": 5, "UserPinPath" : "/dev/shm/sshca/slot5_pwd.txt"}
],
"KeyUsages": [
    {"Endpoint": "/sig/ssh-user-cert", "Identifiers": ["ssh-user-key"], "MaxValidity": 2592000},
    {"Endpoint": "/sig/blob", "Identifiers": ["blob-sign-key"]}
]
}
EOF
    ssh -A cortana.corp.yahoo.com  sudo rm -rf config || true
    ssh -A cortana.corp.yahoo.com  mkdir -p config  || true
    scp certsignd_config.json cortana.corp.yahoo.com:config/certsignd_config.json

    cat <<EOF > Dockerfile
FROM docker.ouroath.com:4443/paranoids/certsignd-pkcs11
USER root
RUN mkdir -p /var/log/crypki && chown ysshuca /var/log/crypki
USER ysshuca
RUN touch /var/log/crypki/server.log
COPY crypki /usr/bin/crypki
COPY config/certsignd_config.json /opt/sshca/config/certsignd_config.json
EOF
     scp Dockerfile cortana.corp.yahoo.com:Dockerfile
     ssh -A cortana.corp.yahoo.com  sudo docker build -t update-crypki .

    ssh -A cortana.corp.yahoo.com  sudo docker rm -f update-crypki || true
    ssh -A cortana.corp.yahoo.com  sudo docker run -v /opt/sshca/CSD:/opt/sshca/CSD:ro -v /dev/shm/sshca:/dev/shm/sshca -v /etc/hosts:/etc/hosts:ro --restart=always --name update-crypki --net=host -h cortana.corp.yahoo.com -d update-crypki

    ssh -A cortana.corp.yahoo.com  sudo docker ps -a
}

run_performance_test() {
    local port=$1

    banner "running performance test"

    banner "test GetUserSSHCertificateSigningKey"
    ssh cortana.corp.yahoo.com  /tmp/ghz/ghz \
    --proto proto/sign.proto \
    --call v3.Signing.GetUserSSHCertificateSigningKey \
    --skipTLS \
    --cacert /opt/sshca/CSD/tls_ca_1.crt \
    --cert /opt/sshca/CSD/tls_server.crt \
    --key /opt/sshca/CSD/tls_server.key \
    -i googleapis/ \
    -D json/GetUserSSHCertificateSigningKey.json \
    0.0.0.0:${port}

    banner "test PostUserSSHCertificate sequentially"
    ssh cortana.corp.yahoo.com  /tmp/ghz/ghz \
    --proto proto/sign.proto \
    --call v3.Signing.PostUserSSHCertificate \
    --skipTLS \
    --cacert /opt/sshca/CSD/tls_ca_1.crt \
    --cert /opt/sshca/CSD/tls_server.crt \
    --key /opt/sshca/CSD/tls_server.key \
    -i googleapis/ \
    --concurrency 1 \
    -D json/PostUserSSHCertificate.json \
    0.0.0.0:${port}

    banner "test PostUserSSHCertificate concurrently"
    ssh cortana.corp.yahoo.com  /tmp/ghz/ghz \
    --proto proto/sign.proto \
    --call v3.Signing.PostUserSSHCertificate \
    --skipTLS \
    --cacert /opt/sshca/CSD/tls_ca_1.crt \
    --cert /opt/sshca/CSD/tls_server.crt \
    --key /opt/sshca/CSD/tls_server.key \
    -i googleapis/ \
    --concurrency 5 \
    -D json/PostUserSSHCertificate.json \
    0.0.0.0:${port}
}

build_performance_binary
prepare_proto_files
prepare_json_files
prepare_new_crypki
run_performance_test 4443
run_performance_test 6443
cleanup
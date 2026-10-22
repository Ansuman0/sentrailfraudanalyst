#!/bin/bash
# First boot of the Sentrail host (Ubuntu 22.04): Docker, Compose plugin, AWS CLI. The app itself is deployed by GitHub.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl unzip jq

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
apt-get update
mkdir -p /etc/docker
echo '{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"5"}}' > /etc/docker/daemon.json   # logs must not fill the disk
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker

curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp && /tmp/aws/install

systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service || true   # preinstalled on Ubuntu AMIs
install -d -m 750 /opt/sentrail
# Auto-start after stop/start is installed by scripts/deploy.sh (sentrail.service); it needs only Docker enabled at boot, done above.

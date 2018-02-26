#!/bin/sh

set -e

go build

export PATH=$PWD:$PATH

PVE_HOST="10.192.40.2"
PVE_USER="go"
PVE_REALM="pve"
PVE_PASSWD="gopasswd"
VM_NAME="test"

docker-machine rm --force $VM_NAME >/dev/null 2>&1 || true

docker-machine --debug \
    create \
    --driver proxmox-ve \
    --proxmox-host $PVE_HOST \
    --proxmox-user $PVE_USER \
    --proxmox-realm $PVE_REALM \
    --proxmox-password $PVE_PASSWD \
    $VM_NAME

# Docker Machine Driver - BETA

The incomplete state is over, as I have a working configuration:

* Build
* Create your own `boot2docker` ISO to have the guest agent integrated [boot2docker Pull 1319](https://github.com/boot2docker/boot2docker/pull/1319)
* 

PVE_NODE="proxmox4"
PVE_HOST="proxmox4.exirius.local"
PVE_USER="docker"
PVE_MEMORY=1
PVE_REALM="pve"
PVE_PASSWD="docker1234"
PVE_POOL="docker-machine"
PVE_STORAGE="local-zfs"
PVE_STORAGE_TYPE="RAW"
PVE_IMAGE_FILE="isodump-linux-generell:iso/boot2docker-andi.iso"
VM_NAME="boot2docker"

docker-machine rm --force $VM_NAME >/dev/null 2>&1 || true

docker-machine --debug \
    create \
    --driver proxmox-ve \
    --proxmox-host $PVE_HOST \
    --proxmox-user $PVE_USER \
    --proxmox-realm $PVE_REALM \
    --proxmox-password $PVE_PASSWD \
    --proxmox-node $PVE_NODE \
    --proxmox-memory-gb $PVE_MEMORY \
    --proxmox-image-file "$PVE_IMAGE_FILE" \
    --proxmox-storage $PVE_STORAGE \
    --proxmox-pool $PVE_POOL \
    --proxmox-storage-type $PVE_STORAGE_TYPE \
    $* \
    $VM_NAME 

eval $(docker-machine env boot2docker)

docker ps

# Docker Machine Driver - BETA

The incomplete state is over, as I have a working configuration:

* [Download](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/releases/tag/v1) or build your own driver
* Copy to some location that is in your path
* Check if it works:

        $ docker-machine create --driver proxmox-ve --help | grep -c proxmox
        14

* Create your own `boot2docker` ISO to have the guest agent integrated [boot2docker Pull 1319](https://github.com/boot2docker/boot2docker/pull/1319) ([Direct Download in my fork](https://github.com/lnxbil/boot2docker/releases/tag/2018-09-16))
* Create a script with the following contents and adapt to your needs:

```sh
PVE_NODE="proxmox4"
PVE_HOST="proxmox4.local"
PVE_USER="docker"
PVE_MEMORY=1
PVE_REALM="pve"
PVE_PASSWD="docker1234"
PVE_POOL="docker-machine"
PVE_STORAGE="zfs"
PVE_STORAGE_TYPE="RAW"
PVE_IMAGE_FILE="isos:iso/boot2docker-PR1319.iso"
VM_NAME="boot2docker"

docker-machine rm --force $VM_NAME >/dev/null 2>&1 || true

docker-machine --debug \
    create \
    --driver proxmox-ve \
    --proxmox-host $PVE_HOST \
    --proxmox-user $PVE_USER \
    --proxmox-realm $PVE_REALM \
    --proxmox-password $PVE_PASSWD 
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
```

## Preparing a special test user in PVE

If you want to test this docker-machine driver, i strongly recommend to secure it properly.
Best way to do this to create a special user that has its own pool and storage for creating
the test machines.

Here is what I use (based on ZFS):

* create a pool for use as `--proxmox-pool docker-machine`

        pvesh create /pools -poolid docker-machine

* create an user `docker-machine` with password `D0ck3rS3cr3t`

        pvesh create /access/users -userid docker-machine@pve -password D0ck3rS3cr3t

* creating a special ZFS dataset and use it as PVE storage

        zfs create -o refquota=50G rpool/proxmox/docker-machine
        zfs create zpool/proxmox/docker-machine/iso
        pvesh create /storage -storage docker-machine -type zfspool -pool rpool/proxmox/docker-machine
        pvesh create /storage -storage docker-machine-iso -type dir -path /zpool/proxmox/docker-machine/iso -content iso
        pvesh set /pools/docker-machine -storage docker-machine
        pvesh set /pools/docker-machine -storage docker-machine-iso

* set proper permissions for the user

        pvesh set /access/acl -path /pool/docker-machine -roles PVEVMAdmin,PVEDatastoreAdmin,PVEPoolAdmin -users docker-machine@pve



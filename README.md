# Docker Machine Driver for Proxmox VE - BETA

The incomplete state is over, as I have a working configuration:

* [Download](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/releases/tag/v2) and copy it into your `PATH` (don't forget to `chmod +x`) or build your own driver
* Check if it works:

        $ docker-machine create --driver proxmox-ve --help | grep -c proxmox
        16

* Use a recent, e.g. `1.5.4` version of [RancherOS](https://github.com/rancher/os/releases) and copy the
  `rancheros-proxmoxve.iso` to your iso image storage on your PVE
* Create a script with the following contents and adapt to your needs:

```sh
PVE_NODE="proxmox"
PVE_HOST="proxmox"
PVE_USER="docker"
PVE_MEMORY=2
PVE_REALM="pve"
PVE_PASSWD="D0ck3rS3cr3t"
PVE_POOL="docker-machine"
PVE_STORAGE="zfs"
PVE_STORAGE_TYPE="RAW"
PVE_IMAGE_FILE="isos:docker-machine-iso/rancheros-proxmoxve.iso"
VM_NAME="proxmox-rancher"

GUEST_USERNAME="docker"
GUEST_PASSWORD="tcuser"

docker-machine rm --force $VM_NAME >/dev/null 2>&1 || true

docker-machine --debug \
    create \
    --driver proxmox-ve \
    --proxmox-host $PVE_HOST \
    --proxmox-user $PVE_USER \
    --proxmox-realm $PVE_REALM \
    --proxmox-password $PVE_PASSWD  \
    --proxmox-node $PVE_NODE \
    --proxmox-memory-gb $PVE_MEMORY \
    --proxmox-image-file "$PVE_IMAGE_FILE" \
    --proxmox-storage $PVE_STORAGE \
    --proxmox-pool $PVE_POOL \
    --proxmox-storage-type $PVE_STORAGE_TYPE \
    \
    --proxmox-guest-username $GUEST_USERNAME \
    --proxmox-guest-password $GUEST_PASSWORD \
    \
    --proxmox-resty-debug \
    --proxmox-driver-debug \
    \
    $* \
    $VM_NAME 

eval $(docker-machine env $VM_NAME)

docker ps
```

And start it up. At the first run, it is adiveable to not comment out the `debug` flags. If everything works as expected, you can remove them.

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



## Changes

### Version 2

* exclusive RancherOS support due to their special Proxmox VE iso files
* adding wait cycles for asynchronous background tasks, e.g.  `create`, `stop` etc.
* use one logger engine
* add guest username, password and ssh-port as new command line arguments
* more and potentially better error handling

### Version 1

* Initial Version
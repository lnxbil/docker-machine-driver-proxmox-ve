# Docker Machine Driver for Proxmox VE

The incomplete state is over, as I have a working configuration:

* [Download](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/releases/tag/v3) and copy it into your `PATH` (don't forget to `chmod +x`) or build your own driver
* Check if it works:

        $ docker-machine create --driver proxmoxve --help | grep -c proxmox
        19

* Use a recent, e.g. `1.5.5` version of [RancherOS](https://github.com/rancher/os/releases) and copy the
  `rancheros-proxmoxve-autoformat.iso` to your iso image storage on your PVE
* Create a script with the following contents and *adapt to your needs*:

```sh
PVE_NODE="proxmox-docker-machine"
PVE_HOST="192.168.1.10"

PVE_USER="docker-machine"
PVE_REALM="pve"
PVE_PASSWD="D0ck3rS3cr3t"

PVE_STORAGE_NAME="docker-machine"
PVE_STORAGE_SIZE="4"
PVE_POOL="docker-machine"

SSH_USERNAME="docker"
SSH_PASSWORD="tcuser"

PVE_MEMORY=2
PVE_CPU_CORES=4
PVE_IMAGE_FILE="docker-machine-iso:iso/rancheros-proxmoxve-autoformat-v1.5.5.iso"
VM_NAME="docker-rancher"

docker-machine rm --force $VM_NAME >/dev/null 2>&1 || true

docker-machine --debug \
    create \
    --driver proxmoxve \
    --proxmoxve-proxmox-host $PVE_HOST \
    --proxmoxve-proxmox-node $PVE_NODE \
    --proxmoxve-proxmox-user-name $PVE_USER \
    --proxmoxve-proxmox-user-password $PVE_PASSWD \
    --proxmoxve-proxmox-realm $PVE_REALM \
    --proxmoxve-proxmox-pool $PVE_POOL \
    \
    --proxmoxve-vm-storage-path $PVE_STORAGE_NAME \
    --proxmoxve-vm-storage-size $PVE_STORAGE_SIZE \
    --proxmoxve-vm-cpu-cores $PVE_CPU_CORES \
    --proxmoxve-vm-memory $PVE_MEMORY \
    --proxmoxve-vm-image-file "$PVE_IMAGE_FILE" \
    \
    --proxmoxve-ssh-username $SSH_USERNAME \
    --proxmoxve-ssh-password $SSH_PASSWORD \
    \
    --proxmoxve-debug-resty \
    --proxmoxve-debug-driver \
    \
    $VM_NAME


eval $(docker-machine env $VM_NAME)

docker ps
```

And start it up. At the first run, it is advisable to not comment out the `debug` flags. If everything works as expected, you can remove them.

## Preparing a special test user in PVE

If you want to test this docker-machine driver, i strongly recommend to secure it properly.
Best way to do this to create a special user that has its own pool and storage for creating
the test machines. This corresponds to the example above.

Here is what I use (based on ZFS):

* create a pool for use as `--proxmoxve-proxmox-pool docker-machine`

        pvesh create /pools -poolid docker-machine

* create an user `docker-machine` with password `D0ck3rS3cr3t`

        pvesh create /access/users -userid docker-machine@pve -password D0ck3rS3cr3t

* creating a special ZFS dataset and use it as PVE storage

        zfs create -o refquota=50G rpool/docker-machine-test
        zfs create rpool/docker-machine-test/iso
        pvesh create /storage -storage docker-machine -type zfspool -pool rpool/docker-machine-test
        pvesh create /storage -storage docker-machine-iso -type dir -path /rpool/docker-machine-test/iso -content iso
        pvesh set /pools/docker-machine -storage docker-machine
        pvesh set /pools/docker-machine -storage docker-machine-iso

* set proper permissions for the user

        pvesh set /access/acl -path /pool/docker-machine -roles PVEVMAdmin,PVEDatastoreAdmin,PVEPoolAdmin -users docker-machine@pve

If you have additional test storages, you can also add them easily:

        pvesh set /pools/docker-machine -storage nfs
        pvesh set /pools/docker-machine -storage lvm
        pvesh set /pools/docker-machine -storage directory

Ceph is currently untested due to the lack of a test environment. If you want to step in, please open an issue.

## Changes

### Version 3

* Renaming driver from `proxmox-ve` to `proxmoxve` due to identification problem with RancherOS's K8S implementation (Thanks to [`@Sellto` for reporting #16](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/issues/16))
* fixing issue with created disk detection (Thanks to [`@Sellto` for reporting #16](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/issues/16))
* Add `IPAddress` property needed by rancher to know the ip address of the created VM. (`@Sellto`)
* Change the name of each flag for better display in the rancher `Node Templates` (`@Sellto`)
* Add number of `CPU cores configuration paramater`. (`@Sellto`)
* LVM-thin fixes (`@vstconsulting`)
* Bridge and VLAN tag support (`@bemanuel`)
* Fixing filename detection including NFS support

### Version 2

* exclusive RancherOS support due to their special Proxmox VE iso files
* adding wait cycles for asynchronous background tasks, e.g.  `create`, `stop` etc.
* use one logger engine
* add guest username, password and ssh-port as new command line arguments
* more and potentially better error handling

### Version 1

* Initial Version

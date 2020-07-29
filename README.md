# Docker Machine Driver for Proxmox VE

This driver can be used to kickstart a VM in Proxmox VE to be used with Docker/Docker Machine.

* [Download](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/releases/tag/v4) and copy it into your `PATH` (don't forget to `chmod +x`) or build your own driver
* Check if it works:

        $ docker-machine create --driver proxmoxve --help | grep -c proxmox
        35

## Operation

Now you have two modes of operation:
* use an iso to install a Docker distribution (e.g. RancherOS)
* use a previously created cloud-init-based image VM template as a base

There are also other options to customize your VM which are not shown here, so
please feel free to explore them with `docker-machine create --driver proxmoxve --help`

### Preparing a special test user in PVE

If you want to test this docker-machine driver, i strongly recommend to secure it properly.
Best way to do this to create a special user that has its own pool and storage for creating
the test machines. This corresponds to the examples below.

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

Ceph is currently not directly tested by me, but there are [fine people](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/issues/32)
out there wo tried it.


### Clone VM

This approach uses a predefined VM template with cloud-init support to be cloned
and used. There a lot of ways to do that, here is an adopted one
(courtesy of [@travisghansen](https://github.com/lnxbil/docker-machine-driver-proxmox-ve/pull/34#issuecomment-665277775)):

```sh
#!/bin/bash

set -x
set -e

export IMGID=9007
export BASE_IMG="debian-10-openstack-amd64.qcow2"
export IMG="debian-10-openstack-amd64-${IMGID}.qcow2"
export STORAGEID="docker-machine"

if [ ! -f "${BASE_IMG}" ];then
  wget https://cloud.debian.org/images/cloud/OpenStack/current-10/debian-10-openstack-amd64.qcow2
fi

if [ ! -f "${IMG}" ];then
  cp -f "${BASE_IMG}" "${IMG}"
fi

# prepare mounts
guestmount -a ${IMG} -m /dev/sda1 /mnt/tmp/
mount --bind /dev/ /mnt/tmp/dev/
mount --bind /proc/ /mnt/tmp/proc/

# get resolving working
mv /mnt/tmp/etc/resolv.conf /mnt/tmp/etc/resolv.conf.orig
cp -a --force /etc/resolv.conf /mnt/tmp/etc/resolv.conf

# install desired apps
chroot /mnt/tmp /bin/bash -c "apt-get update"
chroot /mnt/tmp /bin/bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y net-tools curl qemu-guest-agent nfs-common open-iscsi lsscsi sg3-utils multipath-tools scsitools"

# https://www.electrictoolbox.com/sshd-hostname-lookups/
sed -i 's:#UseDNS no:UseDNS no:' /mnt/tmp/etc/ssh/sshd_config

sed -i '/package-update-upgrade-install/d' /mnt/tmp/etc/cloud/cloud.cfg

cat > /mnt/tmp/etc/cloud/cloud.cfg.d/99_custom.cfg << '__EOF__'
#cloud-config

# Install additional packages on first boot
#
# Default: none
#
# if packages are specified, this apt_update will be set to true
#
# packages may be supplied as a single package name or as a list
# with the format [<package>, <version>] wherein the specifc
# package version will be installed.
#packages:
# - qemu-guest-agent
# - nfs-common

ntp:
  enabled: true

# datasource_list: [ NoCloud, ConfigDrive ]
__EOF__

cat > /mnt/tmp/etc/multipath.conf << '__EOF__'
defaults {
    user_friendly_names yes
    find_multipaths yes
}
__EOF__

# enable services
chroot /mnt/tmp systemctl enable open-iscsi.service || true
chroot /mnt/tmp systemctl enable multipath-tools.service || true

# restore systemd-resolved settings
mv /mnt/tmp/etc/resolv.conf.orig /mnt/tmp/etc/resolv.conf

# umount everything
umount /mnt/tmp/dev
umount /mnt/tmp/proc
umount /mnt/tmp

# create template
qm create ${IMGID} --memory 512 --net0 virtio,bridge=vmbr0
qm importdisk ${IMGID} ${IMG} ${STORAGEID} --format qcow2
qm set ${IMGID} --scsihw virtio-scsi-pci --scsi0 ${STORAGEID}:vm-${IMGID}-disk-0
qm set ${IMGID} --ide2 ${STORAGEID}:cloudinit
qm set ${IMGID} --boot c --bootdisk scsi0
qm set ${IMGID} --serial0 socket --vga serial0
qm template ${IMGID}

# set host cpu, ssh key, etc
qm set ${IMGID} --scsihw virtio-scsi-pci
qm set ${IMGID} --cpu host
qm set ${IMGID} --agent enabled=1
qm set ${IMGID} --autostart
qm set ${IMGID} --onboot 1
qm set ${IMGID} --ostype l26
qm set ${IMGID} --ipconfig0 "ip=dhcp"
```

Adapt to fit your needs and run it on your Proxmox VE until it works without
any problems and creates a template in your Proxmox VE. You may need to install
`libguestfs-tools`.

After the image is created, you can start to use the machine driver to create
new VMs:

```sh
#!/bin/sh
set -ex

export PATH=$PWD:$PATH

PVE_NODE="proxmox"
PVE_HOST="192.168.1.5"

PVE_USER="docker-machine"
PVE_REALM="pve"
PVE_PASSWD="D0ck3rS3cr3t"

PVE_STORAGE_NAME="${1:-docker-machine}"
PVE_POOL="docker-machine"

VM_NAME="docker-clone"

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
    --proxmoxve-provision-strategy clone \
    --proxmoxve-ssh-username 'debian' \
    --proxmoxve-ssh-password 'geheim' \
    --proxmoxve-vm-clone-vmid 9007 \
    \
    --proxmoxve-debug-resty \
    --proxmoxve-debug-driver \
    \
    $* \
    \
    $VM_NAME

eval $(docker-machine env $VM_NAME)

docker ps
```


### Rancher OS

* Use a recent, e.g. `1.5.6` version of [RancherOS](https://github.com/rancher/os/releases) and copy the
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
* Run the script

At the first run, it is advisable to not comment out the `debug` flags. If everything works as expected, you can remove them.

## Changes

### Version 4

* support for using clones+cloud-init (@travisghansen)
* enable custom network bridge without vlan tag (@guyguy333)
* including args to choice scsi model (@bemanuel)
* fix remove error, add further flags (@Psayker)

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

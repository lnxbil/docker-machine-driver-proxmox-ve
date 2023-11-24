package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	sshrw "github.com/mosolovsa/go_cat_sshfilerw"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	mssh "github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
	"github.com/labstack/gommon/log"
	"github.com/luthermonson/go-proxmox"
)

// Driver for Proxmox VE
type Driver struct {
	*drivers.BaseDriver
	client *proxmox.Client
	// Top-level strategy for proisioning a new node
	ProvisionStrategy string

	// Basic Authentication for Proxmox VE
	Host     string // Host to connect to
	Node     string // optional, node to create VM on, host used if omitted but must match internal node name
	User     string // username
	Password string // password
	Realm    string // realm, e.g. pam, pve, etc.

	// File to load as boot image RancherOS/Boot2Docker
	ImageFile string // in the format <storagename>:iso/<filename>.iso

	Pool            string // pool to add the VM to (necessary for users with only pool permission)
	Storage         string // internal PVE storage name
	StorageType     string // Type of the storage (currently QCOW2 and RAW)
	DiskSize        string // disk size in GB
	Memory          int    // memory in GB
	StorageFilename string
	Onboot          string // Specifies whether a VM will be started during system bootup.
	Protection      string // Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
	Citype          string // Specifies the cloud-init configuration format.
	NUMA            string // Enable/disable NUMA

	CiEnabled string

	NetModel    string // Net Interface Model, [e1000, virtio, realtek, etc...]
	NetFirewall string // Enable/disable firewall
	NetMtu      string // set nic MTU
	NetBridge   string // bridge applied to network interface
	NetVlanTag  int    // vlan tag

	ScsiController string
	ScsiAttributes string

	VMID          string // VM ID only filled by create()
	VMID_int      int    // Same as VMID but int
	VMIDRange     string // acceptable range of VMIDs
	VMUUID        string // UUID to confirm
	CloneVMID     string // VM ID to clone
	CloneFull     int    // Make a full (detached) clone from parent (defaults to true if VMID is not a template, otherwise false)
	GuestUsername string // user to log into the guest OS to copy the public key
	GuestPassword string // password to log into the guest OS to copy the public key
	GuestSSHPort  int    // ssh port to log into the guest OS to copy the public key
	CPU           string // Emulated CPU type.
	CPUSockets    string // The number of cpu sockets.
	CPUCores      string // The number of cores per socket.
	driverDebug   bool   // driver debugging
}

func (d *Driver) debugf(format string, v ...interface{}) {
	if d.driverDebug {
		log.Infof(format, v...)
	}
}

func (d *Driver) debug(v ...interface{}) {
	if d.driverDebug {
		log.Info(v...)
	}
}

func (d *Driver) connectApi() (client *proxmox.Client, err error) {
	credentials := proxmox.Credentials{
		Username: "root@pam",
		Password: "12345",
	}
	d.client = proxmox.NewClient("https://localhost:8006/api2/json",
		proxmox.WithCredentials(&credentials),
	)

	version, err := client.Version(context.Background())
	if err == nil {
		log.Info(version.Release)
	}
	return d.client, err
}

// GetCreateFlags returns the argument flags for the program
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_PROXMOX_HOST",
			Name:   "proxmoxve-proxmox-host",
			Usage:  "Host to connect to",
			Value:  "192.168.1.253",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_PROXMOX_NODE",
			Name:   "proxmoxve-proxmox-node",
			Usage:  "Node to use (defaults to host)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_PROVISION_STRATEGY",
			Name:   "proxmoxve-provision-strategy",
			Usage:  "Provision strategy (cdrom|clone)",
			Value:  "cdrom",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_PROXMOX_USER_NAME",
			Name:   "proxmoxve-proxmox-user-name",
			Usage:  "User to connect as",
			Value:  "root",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_PROXMOX_USER_PASSWORD",
			Name:   "proxmoxve-proxmox-user-password",
			Usage:  "Password to connect with",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_PROXMOX_REALM",
			Name:   "proxmoxve-proxmox-realm",
			Usage:  "Realm to connect to (default: pam)",
			Value:  "pam",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_PROXMOX_POOL",
			Name:   "proxmoxve-proxmox-pool",
			Usage:  "pool to attach to",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_VMID_RANGE",
			Name:   "proxmoxve-vm-vmid-range",
			Usage:  "range of acceptable vmid values <low>[:<high>]",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_STORAGE_PATH",
			Name:   "proxmoxve-vm-storage-path",
			Usage:  "storage to create the VM volume on",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_STORAGE_SIZE",
			Name:   "proxmoxve-vm-storage-size",
			Usage:  "disk size in GB",
			Value:  "16",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_STORAGE_TYPE",
			Name:   "proxmoxve-vm-storage-type",
			Usage:  "storage type to use (QCOW2 or RAW)",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_SCSI_CONTROLLER",
			Name:   "proxmoxve-vm-scsi-controller",
			Usage:  "scsi controller model (default: virtio-scsi-pci)",
			Value:  "virtio-scsi-pci",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_SCSI_ATTRIBUTES",
			Name:   "proxmoxve-vm-scsi-attributes",
			Usage:  "scsi0 attributes",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "PROXMOXVE_VM_MEMORY",
			Name:   "proxmoxve-vm-memory",
			Usage:  "memory in GB",
			Value:  8,
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_NUMA",
			Name:   "proxmoxve-vm-numa",
			Usage:  "enable/disable NUMA",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CPU",
			Name:   "proxmoxve-vm-cpu",
			Usage:  "Emulatd CPU",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CPU_SOCKETS",
			Name:   "proxmoxve-vm-cpu-sockets",
			Usage:  "number of cpus",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CPU_CORES",
			Name:   "proxmoxve-vm-cpu-cores",
			Usage:  "number of cpu cores",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CLONE_VMID",
			Name:   "proxmoxve-vm-clone-vmid",
			Usage:  "vmid to clone",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "PROXMOXVE_VM_CLONE_FULL",
			Name:   "proxmoxve-vm-clone-full",
			Usage:  "make a full clone or not (0=false, 1=true, 2=use proxmox default logic",
			Value:  2,
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_START_ONBOOT",
			Name:   "proxmoxve-vm-start-onboot",
			Usage:  "make the VM start automatically onboot (0=false, 1=true, ''=default)",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_PROTECTION",
			Name:   "proxmoxve-vm-protection",
			Usage:  "protect the VM and disks from removal (0=false, 1=true, ''=default)",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CITYPE",
			Name:   "proxmoxve-vm-citype",
			Usage:  "cloud-init type (nocloud|configdrive2)",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CIENABLED",
			Name:   "proxmoxve-vm-cienabled",
			Usage:  "cloud-init enabled (implied with clone strategy 0=false, 1=true, ''=default)",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_IMAGE_FILE",
			Name:   "proxmoxve-vm-image-file",
			Usage:  "storage of the image file (e.g. local:iso/rancheros-proxmoxve-autoformat.iso)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_NET_MODEL",
			Name:   "proxmoxve-vm-net-model",
			Usage:  "Net Interface model, default virtio (e1000, virtio, realtek, etc...)",
			Value:  "virtio",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_NET_FIREWALL",
			Name:   "proxmoxve-vm-net-firewall",
			Usage:  "enable/disable firewall (0=false, 1=true, ''=default)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_NET_MTU",
			Name:   "proxmoxve-vm-net-mtu",
			Usage:  "set nic mtu (''=default)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_NET_BRIDGE",
			Name:   "proxmoxve-vm-net-bridge",
			Usage:  "bridge to attach network to",
			Value:  "", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
		},
		mcnflag.IntFlag{
			EnvVar: "PROXMOXVE_VM_NET_TAG",
			Name:   "proxmoxve-vm-net-tag",
			Usage:  "vlan tag",
			Value:  0,
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_SSH_USERNAME",
			Name:   "proxmoxve-ssh-username",
			Usage:  "Username to log in to the guest OS (default docker for rancheros)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_SSH_PASSWORD",
			Name:   "proxmoxve-ssh-password",
			Usage:  "Password to log in to the guest OS (default tcuser for rancheros)",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "PROXMOXVE_SSH_PORT",
			Name:   "proxmoxve-ssh-port",
			Usage:  "SSH port in the guest to log in to (defaults to 22)",
			Value:  22,
		},
		mcnflag.BoolFlag{
			EnvVar: "PROXMOXVE_DEBUG_DRIVER",
			Name:   "proxmoxve-debug-driver",
			Usage:  "enables debugging in the driver",
		},
	}
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "proxmoxve"
}

// SetConfigFromFlags configures all command line arguments
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.debug("SetConfigFromFlags called")

	d.ProvisionStrategy = flags.String("proxmoxve-provision-strategy")

	// PROXMOX API Connection settings
	d.Host = flags.String("proxmoxve-proxmox-host")
	d.Node = flags.String("proxmoxve-proxmox-node")
	if len(d.Node) == 0 {
		d.Node = d.Host
	}
	d.User = flags.String("proxmoxve-proxmox-user-name")
	d.Password = flags.String("proxmoxve-proxmox-user-password")
	d.Realm = flags.String("proxmoxve-proxmox-realm")
	d.Pool = flags.String("proxmoxve-proxmox-pool")

	// VM configuration
	d.DiskSize = flags.String("proxmoxve-vm-storage-size")
	d.Storage = flags.String("proxmoxve-vm-storage-path")
	d.StorageType = strings.ToLower(flags.String("proxmoxve-vm-storage-type"))
	d.Memory = flags.Int("proxmoxve-vm-memory")
	d.Memory *= 1024
	d.VMIDRange = flags.String("proxmoxve-vm-vmid-range")
	d.CloneVMID = flags.String("proxmoxve-vm-clone-vmid")
	d.CloneFull = flags.Int("proxmoxve-vm-clone-full")
	d.Onboot = flags.String("proxmoxve-vm-start-onboot")
	d.Protection = flags.String("proxmoxve-vm-protection")
	d.Citype = flags.String("proxmoxve-vm-citype")
	d.CiEnabled = flags.String("proxmoxve-vm-cienabled")
	d.ImageFile = flags.String("proxmoxve-vm-image-file")
	d.CPUSockets = flags.String("proxmoxve-vm-cpu-sockets")
	d.CPU = flags.String("proxmoxve-vm-cpu")
	d.CPUCores = flags.String("proxmoxve-vm-cpu-cores")
	d.NetModel = flags.String("proxmoxve-vm-net-model")
	d.NetFirewall = flags.String("proxmoxve-vm-net-firewall")
	d.NetMtu = flags.String("proxmoxve-vm-net-mtu")
	d.NetBridge = flags.String("proxmoxve-vm-net-bridge")
	d.NetVlanTag = flags.Int("proxmoxve-vm-net-tag")
	d.ScsiController = flags.String("proxmoxve-vm-scsi-controller")
	d.ScsiAttributes = flags.String("proxmoxve-vm-scsi-attributes")

	//SSH connection settings
	d.GuestSSHPort = flags.Int("proxmoxve-ssh-port")
	d.GuestUsername = flags.String("proxmoxve-ssh-username")
	d.GuestPassword = flags.String("proxmoxve-ssh-password")

	return nil
}

// GetURL returns the URL for the target docker daemon
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}
	return fmt.Sprintf("tcp://%s:2376", ip), nil
}

// GetMachineName returns the machine name
func (d *Driver) GetMachineName() string {
	return d.MachineName
}

// GetNetBridge returns the bridge
func (d *Driver) GetNetBridge() string {
	return d.NetBridge
}

// GetNetVlanTag returns the vlan tag
func (d *Driver) GetNetVlanTag() int {
	return d.NetVlanTag
}

func (d *Driver) GetNode() (*proxmox.Node, error) {
	n, err := d.client.Node(context.Background(), d.Node)
	if err != nil {
		return nil, err
	}
	return n, err
}

func (d *Driver) OperateVM(operation string) error {

	vm, err := d.GetVM()
	if err != nil {
		return err
	}

	var task proxmox.Task
	var err2 error

	switch operation {
	case "start":
		task, err2 := vm.Start(context.Background())
		log.Debug(task.ID)
		if err2 != nil {
			return err2
		}
	case "stop":
		task, err2 := vm.Stop(context.Background())
		log.Debug(task.ID)
		if err2 != nil {
			return err2
		}
	case "kill":
		task, err2 := vm.Stop(context.Background())
		log.Debug(task.ID)
		if err2 != nil {
			return err2
		}
	case "restart":
		task, err2 := vm.Reset(context.Background())
		log.Debug(task.ID)
		if err2 != nil {
			return err2
		}
	default:
		return errors.New("Invalid operation: " + operation)

	}

	if err2 != nil {
		return err2
	}

	// wait for the start task
	if err2 := task.Wait(context.Background(), time.Duration(5*time.Second), time.Duration(300*time.Second)); err2 != nil {
		return err2
	}

	return err

}

func (d *Driver) GetVM() (*proxmox.VirtualMachine, error) {
	if len(d.VMID) < 1 {
		return nil, errors.New("invalid VMID")
	}

	n, err := d.GetNode()
	if err != nil {
		return nil, err
	}
	vm, err2 := n.VirtualMachine(context.Background(), d.VMID_int)
	if err2 != nil {
		return nil, err2
	}
	return vm, err
}

// GetIP returns the ip
func (d *Driver) GetIP() (string, error) {
	vm, err := d.GetVM()

	if err := vm.WaitForAgent(context.Background(), 300); err != nil {
		return "", err
	}
	net := vm.VirtualMachineConfig.Net0
	iFaces, err3 := vm.AgentGetNetworkIFaces(context.Background())
	if err3 != nil {
		return "", err3
	}
	for _, iface := range iFaces {
		if strings.Contains(strings.ToLower(net), strings.ToLower(iface.HardwareAddress)) {
			for _, ip := range iface.IPAddresses {
				if ip.IPAddressType == "ipv4" {
					d.IPAddress = ip.IPAddress
				}
			}
		}
	}

	if d.IPAddress == "" {
		return "", err
	}

	return d.IPAddress, err
}

// GetSSHHostname returns the ssh host returned by the API
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetSSHPort returns the ssh port, 22 if not specified
func (d *Driver) GetSSHPort() (int, error) {
	return d.GuestSSHPort, nil
}

// GetSSHUsername returns the ssh user name, root if not specified
func (d *Driver) GetSSHUsername() string {
	return d.GuestUsername
}

// GetState returns the state of the VM
func (d *Driver) GetState() (state.State, error) {
	vm, err := d.GetVM()
	if err != nil {
		return state.None, err
	}

	if err := vm.Ping(context.Background()); err != nil {
		return state.None, err
	}

	if vm.IsStopped() {
		return state.Stopped, nil
	}

	if vm.IsRunning() {
		return state.Running, nil
	}

	return state.None, nil
}

// PreCreateCheck is called to enforce pre-creation steps
func (d *Driver) PreCreateCheck() error {

	if d.client == nil {
		client, err := d.connectApi()
		if err != nil {
			return err
		}
		d.client = client
	}

	switch d.ProvisionStrategy {
	case "cdrom":
		// set defaults for cdrom
		// replicating pre-clone behavior of setting a default on the parameter
		if len(d.Storage) < 1 {
			d.Storage = "local"
		}

		if len(d.StorageType) < 1 {
			d.StorageType = "raw"
		}

		if len(d.NetBridge) < 1 {
			d.NetBridge = "vmbr0"
		}

		if len(d.GuestUsername) < 1 {
			d.GuestUsername = "docker"
		}

		if len(d.GuestPassword) < 1 {
			d.GuestPassword = "tcuser"
		}

		// prepare StorageFilename
		switch d.StorageType {
		case "raw":
			fallthrough
		case "qcow2":
			break
		default:
			return fmt.Errorf("storage type '%s' is not supported", d.StorageType)
		}

		node, err := d.client.Node(context.Background(), d.Node)
		if err != nil {
			return err
		}

		storage, err := node.Storage(context.Background(), d.Storage)

		filename := "-disk-0"
		switch storage.Type {
		case "lvmthin":
			fallthrough
		case "zfs":
			fallthrough
		case "ceph":
			if d.StorageType != "raw" {
				return fmt.Errorf("type '%s' on storage '%s' does only support raw", storage.Type, d.Storage)
			}
		case "nfs":
			fallthrough
		case "dir":
			filename += "." + d.StorageType
		}
		// this is not the finale filename, it'll be constructed in Create()
		d.StorageFilename = filename
	case "clone":
		break
	default:
		return fmt.Errorf("invalid provision strategy '%s'", d.ProvisionStrategy)
	}

	return nil
}

// Create creates a new VM with storage
func (d *Driver) Create() error {

	// create and save a new SSH key pair
	d.debug("creating new ssh keypair")
	key, err := d.createSSHKey()
	if err != nil {
		return err
	}

	// !! Workaround for MC-7982.
	key = strings.TrimSpace(key)
	key = fmt.Sprintf("%s %s-%d", key, d.MachineName, time.Now().Unix())
	// !! End workaround for MC-7982.

	// add some random wait time here to help with race conditions in the proxmox api
	// the app could be getting invoked several times in rapid succession so some small waits may be helpful
	mrand.Seed(time.Now().UnixNano()) // Seed the random number generator using the current time (nanoseconds since epoch)
	r := mrand.Intn(5000)
	d.debugf("sleeping %d milliseconds before retrieving next ID", r)
	time.Sleep(time.Duration(r) * time.Millisecond)

	// get next available VMID
	// NOTE: we want to lock in the ID as quickly as possible after retrieving (ie: invoke QemuPost or Clone ASAP to avoid race conditions with other instances)
	d.debug("Retrieving next ID")

	cluster, err := d.client.Cluster(context.Background())
	if err != nil {
		return err
	}

	id, err := cluster.NextID(context.Background())

	d.debugf("Next ID is '%s'", id)
	d.VMID = string(id)
	d.VMID_int = id

	switch d.ProvisionStrategy {
	case "clone":

		clone := &proxmox.VirtualMachineCloneOptions{
			Name:  d.MachineName,
			Full:  1,
			NewID: d.VMID_int,
			Pool:  d.Pool,
		}

		switch d.CloneFull {
		case 0:
			clone.Full = 0
			break
		case 1:
			clone.Full = 1
			clone.Format = d.StorageType
			clone.Storage = d.Storage
			break
		case 2:
			clone.Format = d.StorageType
			clone.Storage = d.Storage
			break
		}

		d.debugf("cloning template id '%s' as vmid '%s'", d.CloneVMID, clone.NewID)

		node, err := d.client.Node(context.Background(), d.Node)

		cloneVmId, err := strconv.Atoi(d.CloneVMID)
		if err != nil {
			return err
		}

		clonevm, err := node.VirtualMachine(context.Background(), cloneVmId)

		newId, task, err := clonevm.Clone(context.Background(), clone)
		if err != nil {
			return err
		}

		// wait for the clone task
		if err := task.Wait(context.Background(), time.Duration(5*time.Second), time.Duration(300*time.Second)); err != nil {
			return err
		}

		// explicity set vmid after clone completion to be sure
		d.VMID = string(newId)
		d.VMID_int = newId

		// resize
		resize := NodesNodeQemuVMIDResizePutParameter{
			Disk: "scsi0",
			Size: d.DiskSize + "G",
		}
		d.debugf("resizing disk '%s' on vmid '%s' to '%s'", resize.Disk, d.VMID, resize.Size)

		err = d.NodesNodeQemuVMIDResizePut(d.Node, d.VMID, &resize)
		if err != nil {
			return err
		}

		// set config values
		d.debugf("setting VM config values for vmid '%s'", d.VMID)
		npp := NodesNodeQemuPostParameter{
			Agent:      "1",
			Autostart:  "1",
			Memory:     d.Memory,
			Sockets:    d.CPUSockets,
			Cores:      d.CPUCores,
			KVM:        "1", // if you test in a nested environment, you may have to change this to 0 if you do not have nested virtualization,
			Citype:     d.Citype,
			Onboot:     d.Onboot,
			Protection: d.Protection,
		}

		if len(d.NetBridge) > 0 {
			npp.Net0, _ = d.generateNetString()
		}

		if len(d.NUMA) > 0 {
			npp.NUMA = d.NUMA
		}

		if len(d.CPU) > 0 {
			npp.CPU = d.CPU
		}

		taskid, err = d.NodesNodeQemuVMIDConfigPost(d.Node, d.VMID, &npp)
		if err != nil {
			return err
		}

		// append newly minted ssh key to existing (if any)
		d.debugf("retrieving existing cloud-init sshkeys from vmid '%s'", d.VMID)
		config, err := d.GetConfig(d.Node, d.CloneVMID)
		if err != nil {
			return err
		}

		var SSHKeys string

		if len(config.Data.SSHKeys) > 0 {
			SSHKeys, err = url.QueryUnescape(config.Data.SSHKeys)
			if err != nil {
				return err
			}

			SSHKeys = strings.TrimSpace(SSHKeys)
			SSHKeys += "\n"
		}

		SSHKeys += key
		SSHKeys = strings.TrimSpace(SSHKeys)

		// specially handle setting sshkeys
		// https://forum.proxmox.com/threads/how-to-use-pvesh-set-vms-sshkeys.52570/
		taskid, err = d.NodesNodeQemuVMIDConfigSetSSHKeys(d.Node, d.VMID, SSHKeys)
		if err != nil {
			return err
		}

		err = d.WaitForTaskToComplete(d.Node, taskid)
		if err != nil {
			return err
		}
		break
	default:
		return fmt.Errorf("invalid provision strategy '%s'", d.ProvisionStrategy)
	}

	// Set the newly minted UUID
	config, err := d.GetConfig(d.Node, d.VMID)
	if err != nil {
		return err
	}
	d.VMUUID = getUUIDFromSmbios1(config.Data.Smbios1)
	d.debugf("VM created with uuid '%s'", d.VMUUID)

	// start the VM
	err = d.Start()
	if err != nil {
		return err
	}

	// let VM start a settle a little
	d.debugf("waiting for VM to start, wait 10 seconds")
	time.Sleep(10 * time.Second)

	// wait for qemu-guest-agent
	err = d.waitForQemuGuestAgent()
	if err != nil {
		return err
	}

	// wait for network to come up
	err = d.waitForNetwork()

	// set the IPAddress
	_, err = d.GetIP()
	if err != nil {
		return err

	}

	switch d.ProvisionStrategy {
	case "cdrom":
		if len(d.GuestPassword) > 0 {
			return d.prepareSSHWithPassword()
		}
		return nil
	case "clone":
		fallthrough
	default:
		return nil
	}
}

func (d *Driver) waitForNetwork() error {
	d.debugf("waiting for VM network to start")
	d.connectApi()

	var up = false
	var ip string
	var err error

	for !up {
		ip, err = d.GetIP()
		if err != nil {
			d.debugf("waiting for VM network to start")
			time.Sleep(5 * time.Second)
		} else {
			if len(ip) > 0 {
				up = true
				d.debugf("VM network started with ip: %s", ip)
			} else {
				d.debugf("waiting for VM network to start")
				time.Sleep(5 * time.Second)
			}
		}
	}

	return nil
}

func (d *Driver) generateNetString() (string, error) {
	var net string = fmt.Sprintf("model=%s,bridge=%s", d.NetModel, d.NetBridge)
	if d.NetVlanTag != 0 {
		net = fmt.Sprintf(net+",tag=%d", d.NetVlanTag)
	}

	if len(d.NetFirewall) > 0 {
		net = fmt.Sprintf(net+",firewall=%s", d.NetFirewall)
	}

	if len(d.NetMtu) > 0 {
		net = fmt.Sprintf(net+",mtu=%s", d.NetMtu)
	}

	return net, nil
}

func (d *Driver) prepareSSHWithPassword() error {
	sshConfig := &ssh.ClientConfig{
		User: d.GetSSHUsername(),
		Auth: []ssh.AuthMethod{
			ssh.Password(d.GuestPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshbasedir := "/home/" + d.GetSSHUsername() + "/.ssh"
	hostname, _ := d.GetSSHHostname()
	port, _ := d.GetSSHPort()
	clientstr := fmt.Sprintf("%s:%d", hostname, port)

	d.debugf("Creating directory '%s'", sshbasedir)
	conn, err := ssh.Dial("tcp", clientstr, sshConfig)
	if err != nil {
		return err
	}
	session, err := conn.NewSession()
	if err != nil {
		return err
	}

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run("mkdir -p " + sshbasedir)
	d.debugf(fmt.Sprintf("%s -> %s", hostname, stdoutBuf.String()))
	session.Close()

	d.debugf("Trying to copy to %s:%s", clientstr, sshbasedir)
	c, err := sshrw.NewSSHclt(clientstr, sshConfig)
	if err != nil {
		return err
	}

	// Open a file
	f, err := os.Open(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return err
	}

	// TODO: always fails with return status 127, but file was copied correclty
	c.WriteFile(f, sshbasedir+"/authorized_keys")
	// if err = c.WriteFile(f, sshbasedir+"/authorized_keys"); err != nil {
	// 	d.debugf("Error on file write: ", err)
	// }

	// Close the file after it has been copied
	defer f.Close()

	return err
}

// Start starts the VM
func (d *Driver) Start() error {
	return d.OperateVM("start")
}

// Stop stopps the VM
func (d *Driver) Stop() error {
	return d.OperateVM("stop")
}

// Restart restarts the VM
func (d *Driver) Restart() error {
	return d.OperateVM("restart")
}

// Kill the VM immediately
func (d *Driver) Kill() error {
	return d.OperateVM("kill")
}

// Remove removes the VM
func (d *Driver) Remove() error {
	vm, err := d.GetVM()
	if err != nil {
		return err
	}

	stopTask, err2 := vm.Stop(context.Background())
	if err2 != nil {
		return err2
	}
	// wait for the stop task
	if err3 := stopTask.Wait(context.Background(), time.Duration(5*time.Second), time.Duration(300*time.Second)); err3 != nil {
		return err3
	}

	deleteTask, err4 := vm.Delete(context.Background())
	if err4 != nil {
		return err4
	}

	// wait for the delete task
	if err5 := deleteTask.Wait(context.Background(), time.Duration(5*time.Second), time.Duration(300*time.Second)); err5 != nil {
		return err5
	}

	return nil
}

// Upgrade is currently a NOOP
func (d *Driver) Upgrade() error {
	return nil
}

// NewDriver returns a new driver
func NewDriver(hostName, storePath string) drivers.Driver {
	return &Driver{
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     "docker",
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) createSSHKey() (string, error) {
	sshKeyPath := d.ResolveStorePath("id_rsa")
	if err := mssh.GenerateSSHKey(sshKeyPath); err != nil {
		return "", err
	}
	key, err := os.ReadFile(sshKeyPath + ".pub")
	if err != nil {
		return "", err
	}
	return string(key), nil
}

// GetKeyPair returns a public/private key pair and an optional error
func GetKeyPair(file string) (string, string, error) {
	// read keys from file
	_, err := os.Stat(file)
	if err == nil {
		priv, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("Failed to read file - %s", err)
			goto genKeys
		}
		pub, err := os.ReadFile(file + ".pub")
		if err != nil {
			fmt.Printf("Failed to read pub file - %s", err)
			goto genKeys
		}
		return string(pub), string(priv), nil
	}

	// generate keys and save to file
genKeys:
	pub, priv, err := GenKeyPair()
	if err != nil {
		return "", "", fmt.Errorf("failed to gen keypair - %s", err)
	}
	err = os.WriteFile(file, []byte(priv), 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to write file - %s", err)
	}
	err = os.WriteFile(file+".pub", []byte(pub), 0644)
	if err != nil {
		return "", "", fmt.Errorf("failed to write pub file - %s", err)
	}

	return pub, priv, nil
}

// GenKeyPair returns a freshly created public/private key pair and an optional error
func GenKeyPair() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	var private bytes.Buffer
	if err := pem.Encode(&private, privateKeyPEM); err != nil {
		return "", "", err
	}

	// generate public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	public := ssh.MarshalAuthorizedKey(pub)
	return string(public), private.String(), nil
}

func getUUIDFromSmbios1(str string) string {
	var re = regexp.MustCompile(`(?m)uuid=([\d\w-]{1,})[,]{0,1}.*$`)
	return re.FindStringSubmatch(fmt.Sprintf("%s", str))[1]
}

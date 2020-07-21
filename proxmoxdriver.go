package dockermachinedriverproxmoxve

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	resty "gopkg.in/resty.v1"

	sshrw "github.com/mosolovsa/go_cat_sshfilerw"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	"github.com/labstack/gommon/log"
)

// Driver for Proxmox VE
type Driver struct {
	*drivers.BaseDriver
	driver *ProxmoxVE

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

	NetBridge  string // bridge applied to network interface
	NetVlanTag int    // vlan tag

	VMID          string // VM ID only filled by create()
	CloneVMID     string // VM ID to clone
	CloneFull     int    // Make a full (detached) clone from parent (defaults to true if VMID is not a template, otherwise false)
	GuestUsername string // user to log into the guest OS to copy the public key
	GuestPassword string // password to log into the guest OS to copy the public key
	GuestSSHPort  int    // ssh port to log into the guest OS to copy the public key
	Sockets       string // The number of cpu sockets.
	Cores         string // The number of cores per socket.
	driverDebug   bool   // driver debugging
	restyDebug    bool   // enable resty debugging
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

func (d *Driver) connectAPI() error {
	if d.driver == nil {
		d.debugf("Create called")

		d.debugf("Connecting to %s as %s@%s with password '%s'", d.Host, d.User, d.Realm, d.Password)
		c, err := GetProxmoxVEConnectionByValues(d.User, d.Password, d.Realm, d.Host)
		d.driver = c
		if err != nil {
			return fmt.Errorf("Could not connect to host '%s' with '%s@%s'", d.Host, d.User, d.Realm)
		}
		if d.restyDebug {
			c.EnableDebugging()
		}
		d.debugf("Connected to PVE version '" + d.driver.Version + "'")
	}
	return nil
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
		mcnflag.IntFlag{
			EnvVar: "PROXMOXVE_VM_MEMORY",
			Name:   "proxmoxve-vm-memory",
			Usage:  "memory in GB",
			Value:  8,
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CPU_SOCKETS",
			Name:   "proxmoxve-vm-cpu-sockets",
			Usage:  "number of cpus",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CPU",
			Name:   "proxmoxve-vm-cpu-cores",
			Usage:  "number of cpu cores",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CLONE_VNID",
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
			EnvVar: "PROXMOXVE_VM_IMAGE_FILE",
			Name:   "proxmoxve-vm-image-file",
			Usage:  "storage of the image file (e.g. local:iso/rancheros-proxmoxve-autoformat.iso)",
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
			Value:  "docker",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_SSH_PASSWORD",
			Name:   "proxmoxve-ssh-password",
			Usage:  "Password to log in to the guest OS (default tcuser for rancheros)",
			Value:  "tcuser",
		},
		mcnflag.IntFlag{
			EnvVar: "PROXMOXVE_SSH_PORT",
			Name:   "proxmoxve-ssh-port",
			Usage:  "SSH port in the guest to log in to (defaults to 22)",
			Value:  22,
		},
		mcnflag.BoolFlag{
			EnvVar: "PROXMOXVE_DEBUG_RESTY",
			Name:   "proxmoxve-debug-resty",
			Usage:  "enables the resty debugging",
		},
		mcnflag.BoolFlag{
			EnvVar: "PROXMOXVE_DEBUG_DRIVER",
			Name:   "proxmoxve-debug-driver",
			Usage:  "enables debugging in the driver",
		},
	}
}

func (d *Driver) ping() bool {
	if d.driver == nil {
		return false
	}

	command := NodesNodeQemuVMIDAgentPostParameter{Command: "ping"}
	err := d.driver.NodesNodeQemuVMIDAgentPost(d.Node, d.VMID, &command)

	if err != nil {
		d.debug(err)
		return false
	}

	return true
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
	d.CloneVMID = flags.String("proxmoxve-vm-clone-vmid")
	d.CloneFull = flags.Int("proxmoxve-vm-clone-full")
	d.Onboot = flags.String("proxmoxve-vm-start-onboot")
	d.Protection = flags.String("proxmoxve-vm-protection")
	d.Citype = flags.String("proxmoxve-vm-citype")
	d.ImageFile = flags.String("proxmoxve-vm-image-file")
	d.Sockets = flags.String("proxmoxve-vm-cpu-sockets")
	d.Cores = flags.String("proxmoxve-vm-cpu-cores")
	d.NetBridge = flags.String("proxmoxve-vm-net-bridge")
	d.NetVlanTag = flags.Int("proxmoxve-vm-net-tag")

	//SSH connection settings
	d.GuestSSHPort = flags.Int("proxmoxve-ssh-port")
	d.GuestUsername = flags.String("proxmoxve-ssh-username")
	d.GuestPassword = flags.String("proxmoxve-ssh-password")

	//SWARM Settings
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")

	//Debug option
	d.driverDebug = flags.Bool("proxmoxve-debug-driver")
	d.restyDebug = flags.Bool("proxmoxve-debug-resty")

	if d.restyDebug {
		d.debug("enabling Resty debugging")
		resty.SetLogger(log.Output())
		resty.SetDebug(true)
	}

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

// GetIP returns the ip
func (d *Driver) GetIP() (string, error) {
	d.connectAPI()
	return d.driver.GetEth0IPv4(d.Node, d.VMID)
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
	err := d.connectAPI()
	if err != nil {
		return state.Paused, err
	}

	if d.ping() {
		return state.Running, nil
	}
	return state.Stopped, nil
}

// PreCreateCheck is called to enforce pre-creation steps
func (d *Driver) PreCreateCheck() error {

	err := d.connectAPI()
	if err != nil {
		return err
	}

	d.debug("Retrieving next ID")
	id, err := d.driver.ClusterNextIDGet(0)
	if err != nil {
		return err
	}
	d.debugf("Next ID was '%s'", id)
	d.VMID = id

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

		// prepare StorageFilename
		switch d.StorageType {
		case "raw":
			fallthrough
		case "qcow2":
			break
		default:
			return fmt.Errorf("storage type '%s' is not supported", d.StorageType)
		}

		storageType, err := d.driver.GetStorageType(d.Node, d.Storage)
		if err != nil {
			return err
		}

		filename := "vm-" + d.VMID + "-disk-1"
		switch storageType {
		case "lvmthin":
			fallthrough
		case "zfs":
			fallthrough
		case "ceph":
			if d.StorageType != "raw" {
				return fmt.Errorf("type '%s' on storage '%s' does only support raw", storageType, d.Storage)
			}
		case "nfs":
			fallthrough
		case "dir":
			filename += "." + d.StorageType
		}
		d.StorageFilename = filename
	case "clone":
		break
	default:
		return fmt.Errorf("invalid provision strategy '%s'", d.ProvisionStrategy)
	}

	// create and save a new SSH key pair
	keyfile := d.GetSSHKeyPath()
	keypath := path.Dir(keyfile)
	d.debugf("Generating new key pair at path '%s'", keypath)
	err = os.MkdirAll(keypath, 0755)
	if err != nil {
		return err
	}
	_, _, err = GetKeyPair(keyfile)

	return err
}

// Create creates a new VM with storage
func (d *Driver) Create() error {

	switch d.ProvisionStrategy {
	case "cdrom":

		volume := NodesNodeStorageStorageContentPostParameter{
			Filename: d.StorageFilename,
			Size:     d.DiskSize + "G",
			VMID:     d.VMID,
		}

		d.debugf("Creating disk volume '%s' with size '%s'", volume.Filename, volume.Size)
		diskname, err := d.driver.NodesNodeStorageStorageContentPost(d.Node, d.Storage, &volume)
		if err != nil {
			return err
		}

		if !strings.HasSuffix(diskname, d.StorageFilename) {
			return fmt.Errorf("returned diskname is not correct: should be '%s' but was '%s'", d.StorageFilename, diskname)
		}

		npp := NodesNodeQemuPostParameter{
			VMID:       d.VMID,
			Agent:      "1",
			Autostart:  "1",
			Memory:     d.Memory,
			Sockets:    d.Sockets,
			Cores:      d.Cores,
			SCSI0:      d.StorageFilename,
			Ostype:     "l26",
			Name:       d.BaseDriver.MachineName,
			KVM:        "1", // if you test in a nested environment, you may have to change this to 0 if you do not have nested virtualization
			Scsihw:     "virtio-scsi-pci",
			Cdrom:      d.ImageFile,
			Ide3:       d.Storage + ":cloudinit",
			Citype:     d.Citype,
			Pool:       d.Pool,
			Onboot:     d.Onboot,
			Protection: d.Protection,
		}

		npp.Net0, _ = d.generateNetString()

		if d.StorageType == "qcow2" {
			npp.SCSI0 = d.Storage + ":" + d.VMID + "/" + volume.Filename
		} else if d.StorageType == "raw" {
			if strings.HasSuffix(volume.Filename, ".raw") {
				// raw files (having .raw) should have the VMID in the path
				npp.SCSI0 = d.Storage + ":" + d.VMID + "/" + volume.Filename
			} else {
				npp.SCSI0 = d.Storage + ":" + volume.Filename
			}
		}
		d.debugf("Creating VM '%s' with '%d' of memory", npp.VMID, npp.Memory)
		taskid, err := d.driver.NodesNodeQemuPost(d.Node, &npp)
		if err != nil {
			return err
		}

		err = d.driver.WaitForTaskToComplete(d.Node, taskid)
		if err != nil {
			return err
		}

		var pub string
		keyfile := d.GetSSHKeyPath()
		pub, _, err = GetKeyPair(keyfile)
		if err != nil {
			return err
		}

		// specially handle setting sshkeys
		// https://forum.proxmox.com/threads/how-to-use-pvesh-set-vms-sshkeys.52570/
		taskid, err = d.driver.NodesNodeQemuVMIDConfigSetSSHKeys(d.Node, d.VMID, pub)
		if err != nil {
			return err
		}

		err = d.driver.WaitForTaskToComplete(d.Node, taskid)
		if err != nil {
			return err
		}
		break
	case "clone":

		// clone
		clone := NodesNodeQemuVMIDClonePostParameter{
			Newid: d.VMID,
			Name:  d.BaseDriver.MachineName,
			Pool:  d.Pool,
		}

		switch d.CloneFull {
		case 0:
			clone.Full = "0"
			break
		case 1:
			clone.Full = "1"
			clone.Format = d.StorageType
			clone.Storage = d.Storage
			break
		case 2:
			clone.Format = d.StorageType
			clone.Storage = d.Storage
			break
		}

		d.debugf("cloning template id '%s' as vmid '%s'", d.CloneVMID, clone.Newid)

		taskid, err := d.driver.NodesNodeQemuVMIDClonePost(d.Node, d.CloneVMID, &clone)
		if err != nil {
			return err
		}

		err = d.driver.WaitForTaskToComplete(d.Node, taskid)
		if err != nil {
			return err
		}

		// resize
		resize := NodesNodeQemuVMIDResizePutParameter{
			Disk: "scsi0",
			Size: d.DiskSize + "G",
		}
		d.debugf("resizing disk '%s' on vmid '%s' to '%s'", resize.Disk, d.VMID, resize.Size)

		err = d.driver.NodesNodeQemuVMIDResizePut(d.Node, d.VMID, &resize)
		if err != nil {
			return err
		}

		// set config values
		d.debugf("setting cloud-init sshkeys for vmid '%s'", d.VMID)
		npp := NodesNodeQemuPostParameter{
			Agent:      "1",
			Autostart:  "1",
			Memory:     d.Memory,
			Sockets:    d.Sockets,
			Cores:      d.Cores,
			KVM:        "1", // if you test in a nested environment, you may have to change this to 0 if you do not have nested virtualization,
			Citype:     d.Citype,
			Onboot:     d.Onboot,
			Protection: d.Protection,
		}

		if len(d.NetBridge) > 0 {
			npp.Net0, _ = d.generateNetString()
		}

		taskid, err = d.driver.NodesNodeQemuVMIDConfigPost(d.Node, d.VMID, &npp)
		if err != nil {
			return err
		}

		// append newly minted ssh key to existing (if any)
		d.debugf("retrieving existing cloud-init sshkeys from vmid '%s'", d.VMID)
		config, err := d.driver.GetConfig(d.Node, d.CloneVMID)
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

		var pub string
		keyfile := d.GetSSHKeyPath()
		pub, _, err = GetKeyPair(keyfile)
		if err != nil {
			return err
		}

		SSHKeys += pub
		SSHKeys = strings.TrimSpace(SSHKeys)

		// specially handle setting sshkeys
		// https://forum.proxmox.com/threads/how-to-use-pvesh-set-vms-sshkeys.52570/
		taskid, err = d.driver.NodesNodeQemuVMIDConfigSetSSHKeys(d.Node, d.VMID, SSHKeys)
		if err != nil {
			return err
		}

		err = d.driver.WaitForTaskToComplete(d.Node, taskid)
		if err != nil {
			return err
		}
		break
	default:
		return fmt.Errorf("invalid provision strategy '%s'", d.ProvisionStrategy)
	}

	err := d.Start()
	if err != nil {
		return err
	}

	switch d.ProvisionStrategy {
	case "cdrom":
		return nil
		//return d.waitAndPrepareSSH()
	case "clone":
		fallthrough
	default:
		return nil
	}
}

func (d *Driver) generateNetString() (string, error) {
	var net string = fmt.Sprintf("virtio,bridge=%s", d.NetBridge)
	if d.NetVlanTag != 0 {
		net = fmt.Sprintf(net+",tag=%d", d.NetVlanTag)
	}

	return net, nil
}

func (d *Driver) waitAndPrepareSSH() error {
	d.debugf("waiting for VM to become active, first wait 10 seconds")
	time.Sleep(10 * time.Second)

	for !d.ping() {
		d.debugf("waiting for VM to become active")
		time.Sleep(2 * time.Second)
	}
	d.debugf("VM is active waiting more")
	time.Sleep(2 * time.Second)

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
	ip, err := d.GetIP()
	if err != nil {
		return err

	}
	d.IPAddress = ip
	d.debugf("driver IP is set as '%s'", d.IPAddress)
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
	err := d.connectAPI()
	if err != nil {
		return err
	}
	taskid, err := d.driver.NodesNodeQemuVMIDStatusStartPost(d.Node, d.VMID)

	if err != nil {
		return err
	}

	err = d.driver.WaitForTaskToComplete(d.Node, taskid)

	return err
}

// Stop stopps the VM
func (d *Driver) Stop() error {
	err := d.connectAPI()
	if err != nil {
		return err
	}
	taskid, err := d.driver.NodesNodeQemuVMIDStatusShutdownPost(d.Node, d.VMID)

	if err != nil {
		return err
	}

	err = d.driver.WaitForTaskToComplete(d.Node, taskid)

	return err
}

// Restart restarts the VM
func (d *Driver) Restart() error {
	err := d.connectAPI()
	if err != nil {
		return err
	}
	taskid, err := d.driver.NodesNodeQemuVMIDStatusRebootPost(d.Node, d.VMID)

	if err != nil {
		return err
	}

	err = d.driver.WaitForTaskToComplete(d.Node, taskid)

	return err
}

// Kill the VM immediately
func (d *Driver) Kill() error {
	err := d.connectAPI()
	if err != nil {
		return err
	}
	taskid, err := d.driver.NodesNodeQemuVMIDStatusStopPost(d.Node, d.VMID)

	if err != nil {
		return err
	}

	err = d.driver.WaitForTaskToComplete(d.Node, taskid)

	return err
}

// Remove removes the VM
func (d *Driver) Remove() error {
	err := d.connectAPI()
	if err != nil {
		return err
	}
	taskid, err := d.driver.NodesNodeQemuVMIDDelete(d.Node, d.VMID)

	if err != nil {
		return err
	}

	err = d.driver.WaitForTaskToComplete(d.Node, taskid)
	return err
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

// GetKeyPair returns a public/private key pair and an optional error
func GetKeyPair(file string) (string, string, error) {
	// read keys from file
	_, err := os.Stat(file)
	if err == nil {
		priv, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("Failed to read file - %s", err)
			goto genKeys
		}
		pub, err := ioutil.ReadFile(file + ".pub")
		if err != nil {
			fmt.Printf("Failed to read pub file - %s", err)
			goto genKeys
		}
		return string(pub), string(priv), nil
	}

	// generate keys and save to file
genKeys:
	pub, priv, err := GenKeyPair()
	err = ioutil.WriteFile(file, []byte(priv), 0600)
	if err != nil {
		return "", "", fmt.Errorf("Failed to write file - %s", err)
	}
	err = ioutil.WriteFile(file+".pub", []byte(pub), 0644)
	if err != nil {
		return "", "", fmt.Errorf("Failed to write pub file - %s", err)
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

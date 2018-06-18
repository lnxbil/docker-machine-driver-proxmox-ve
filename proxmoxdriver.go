package dockermachinedriverproxmoxve

import (
	"fmt"
	"strings"

	"gopkg.in/resty.v1"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	"github.com/labstack/gommon/log"
)

// Driver for Proxmox VE
type Driver struct {
	*drivers.BaseDriver
	driver *ProxmoxVE

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

	VMID string // VM ID only filled by create()

	driverDebug bool // driver debugging
	restyDebug  bool // enable resty debugging
}

func (d *Driver) debugf(format string, v ...interface{}) {
	if d.driverDebug {
		log.Infof(fmt.Sprintf(format, v...))
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

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_HOST",
			Name:   "proxmox-host",
			Usage:  "Host to connect to",
			Value:  "192.168.1.253",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_DISKSIZE_GB",
			Name:   "proxmox-disksize-gb",
			Usage:  "disk size in GB",
			Value:  "16",
		},
		mcnflag.IntFlag{
			EnvVar: "PROXMOX_MEMORY_GB",
			Name:   "proxmox-memory-gb",
			Usage:  "memory in GB",
			Value:  8,
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_STORAGE",
			Name:   "proxmox-storage",
			Usage:  "storage to create the VM volume on",
			Value:  "local",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_NODE",
			Name:   "proxmox-node",
			Usage:  "to to use (defaults to host)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_USER",
			Name:   "proxmox-user",
			Usage:  "User to connect as",
			Value:  "root",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_REALM",
			Name:   "proxmox-realm",
			Usage:  "Realm to connect to (default: pam)",
			Value:  "pam",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_PASSWORD",
			Name:   "proxmox-password",
			Usage:  "Password to connect with",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_IMAGE_FILE",
			Name:   "proxmox-image-file",
			Usage:  "storage of the image file (e.g. local:iso/rancheros.iso)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_POOL",
			Name:   "proxmox-pool",
			Usage:  "pool to attach to",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_STORAGE_TYPE",
			Name:   "proxmox-storage-type",
			Usage:  "storage type to use (QCOW2 or RAW)",
			Value:  "raw",
		},
		mcnflag.BoolFlag{
			Name:  "proxmox-resty-debug",
			Usage: "enables the resty debugging",
		},
		mcnflag.BoolFlag{
			Name:  "proxmox-driver-debug",
			Usage: "enables debugging in the driver",
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
	return "proxmox-ve"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.debug("SetConfigFromFlags called")
	d.ImageFile = flags.String("proxmox-image-file")
	d.Host = flags.String("proxmox-host")
	d.Node = flags.String("proxmox-node")
	if len(d.Node) == 0 {
		d.Node = d.Host
	}
	d.User = flags.String("proxmox-user")
	d.Realm = flags.String("proxmox-realm")
	d.Pool = flags.String("proxmox-pool")
	d.Password = flags.String("proxmox-password")
	d.DiskSize = flags.String("proxmox-disksize-gb")
	d.Storage = flags.String("proxmox-storage")
	d.StorageType = strings.ToLower(flags.String("proxmox-storage-type"))
	d.Memory = flags.Int("proxmox-memory-gb")
	d.Memory *= 1024

	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")

	d.driverDebug = flags.Bool("proxmox-driver-debug")
	d.restyDebug = flags.Bool("proxmox-resty-debug")
	if d.restyDebug {
		d.debug("enabling Resty debugging")
		resty.SetDebug(true)
	}

	return nil
}

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

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetIP() (string, error) {
	d.connectAPI()
	return d.driver.GetEth0IPv4(d.Node, d.VMID)
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

//func (d *Driver) GetSSHKeyPath() string {
//	return d.GetSSHKeyPath() + ".pub"
//}

func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = 22
	}

	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "docker"
	}

	return d.SSHUser
}

func (d *Driver) GetState() (state.State, error) {
	err := d.connectAPI()
	if err != nil {
		return state.Paused, err
	}

	if d.ping() {
		return state.Running, nil
	}
	return state.Paused, nil
}

func (d *Driver) PreCreateCheck() error {

	switch d.StorageType {
	case "raw":
		fallthrough
	case "qcow2":
		break
	default:
		return fmt.Errorf("storage type '%s' is not supported", d.StorageType)
	}

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
	case "dir":
		filename += "." + d.StorageType
	}
	d.StorageFilename = filename

	return nil
}

func (d *Driver) Create() error {

	volume := NodesNodeStorageStorageContentPostParameter{
		Filename: d.StorageFilename,
		Size:     d.DiskSize + "G",
		VMID:     d.VMID,
	}

	d.debugf("Creating disk volume '%s' with size '%s'", volume.Filename, volume.Size)
	err := d.driver.NodesNodeStorageStorageContentPost(d.Node, d.Storage, &volume)
	if err != nil {
		return err
	}

	npp := NodesNodeQemuPostParameter{
		VMID:      d.VMID,
		Agent:     "1",
		Autostart: "1",
		Memory:    d.Memory,
		Cores:     "4",
		Net0:      "virtio,bridge=vmbr0",
		SCSI0:     d.Storage + ":" + volume.Filename,
		Ostype:    "l26",
		Name:      d.BaseDriver.MachineName,
		KVM:       "1", // if you test in a nested environment, you may have to change this to 0 if you do not have nested virtualization
		Cdrom:     d.ImageFile,
		Pool:      d.Pool,
	}

	if d.StorageType == "qcow2" {
		npp.SCSI0 = d.Storage + ":" + d.VMID + "/" + volume.Filename
	}
	d.debugf("Creating VM '%s' with '%d' of memory", npp.VMID, npp.Memory)
	err = d.driver.NodesNodeQemuPost(d.Node, &npp)
	if err != nil {
		return err
	}

	d.Start()

	return nil
}

func (d *Driver) Start() error {
	err := d.connectAPI()
	if err != nil {
		return err
	}
	return d.driver.NodesNodeQemuVMIDStatusStartPost(d.Node, d.VMID)
}

func (d *Driver) Stop() error {
	//d.MockState = state.Stopped
	return nil
}

func (d *Driver) Restart() error {
	d.Stop()
	d.Start()
	//d.MockState = state.Running
	return nil
}

func (d *Driver) Kill() error {
	//d.MockState = state.Stopped
	return nil
}

func (d *Driver) Remove() error {
	err := d.connectAPI()
	if err != nil {
		return err
	}
	return d.driver.NodesNodeQemuVMIDDelete(d.Node, d.VMID)
}

func (d *Driver) Upgrade() error {
	return nil
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return &Driver{
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     "docker",
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

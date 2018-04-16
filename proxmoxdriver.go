package dockermachinedriverproxmoxve

import (
	"fmt"
	"os"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	"github.com/labstack/gommon/log"
)

// Driver for Proxmox VE
type Driver struct {
	*drivers.BaseDriver

	// Basic Authentication for Proxmox VE
	Host     string // Host to connect to
	Node     string // optional, node to create VM on, host used if omitted but must match internal node name
	User     string // username
	Password string // password
	Realm    string // realm, e.g. pam, pve, etc.

	// File to load as boot image RancherOS/Boot2Docker
	ImageFile string // in the format <storagename>:iso/<filename>.iso

	Storage  string // internal PVE storage name
	DiskSize string // disk size in GB
	Memory   int    // memory in GB
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
	}
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "proxmox-ve"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	log.Debugf("SetConfigFromFlags called")
	d.ImageFile = flags.String("proxmox-image-file")
	d.Host = flags.String("proxmox-host")
	d.Node = flags.String("proxmox-node")
	if len(d.Node) == 0 {
		d.Node = d.Host
	}
	d.User = flags.String("proxmox-user")
	d.Realm = flags.String("proxmox-realm")
	d.Password = flags.String("proxmox-password")
	d.DiskSize = flags.String("proxmox-disksize-gb")
	d.Storage = flags.String("proxmox-storage")
	d.Memory = flags.Int("proxmox-memory-gb")
	d.Memory *= 1024

	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")

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
	// if d.MockState == state.Error {
	// 	return "", fmt.Errorf("Unable to get ip")
	// }
	// if d.MockState == state.Timeout {
	// 	select {} // Loop forever
	// }
	// if d.MockState != state.Running {
	// 	return "", drivers.ErrHostIsNotRunning
	// }
	return "127.0.0.1", nil
}

func (d *Driver) GetSSHHostname() (string, error) {
	return "", nil
}

func (d *Driver) GetSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

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
	return state.Paused, nil
}

func (d *Driver) Create() error {
	log.Warn("Create called")

	log.Warnf("Connecting to %s as %s@%s with password '%s'\n", d.Host, d.User, d.Realm, d.Password)
	c, err := GetProxmoxVEConnectionByValues(d.User, d.Password, d.Realm, d.Host)

	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	log.Warn("Connected to version '" + c.Version + "'")

	log.Warnf("Retrieving next ID\n")
	id, err := c.ClusterNextIDGet(0)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	log.Warnf("Next ID was '%s'\n", id)

	volume := NodesNodeStorageStorageContentPostParameter{
		Filename: "vm-" + id + "-disk-1.qcow2",
		Size:     d.DiskSize + "G",
		VMID:     id,
	}

	log.Warnf("Creating disk volume '%s' with size '%s'\n", volume.Filename, volume.Size)
	err = c.NodesNodeStorageStorageContentPost(d.Node, d.Storage, &volume)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	npp := NodesNodeQemuPostParameter{
		VMID:      id,
		Agent:     "1",
		Autostart: "1",
		Memory:    d.Memory,
		Cores:     "4",
		Net0:      "virtio,bridge=vmbr0",
		SCSI0:     d.Storage + ":" + id + "/" + volume.Filename,
		Ostype:    "l26",
		Name:      d.BaseDriver.MachineName,
		KVM:       "1", // if you test in a nested environment, you may have to change this to 0 if you do not have nested virtualization
		Cdrom:     d.ImageFile,
	}
	log.Warnf("Creating VM '%s' with '%d' of memory\n", npp.VMID, npp.Memory)
	err = c.NodesNodeQemuPost(d.Node, &npp)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	log.Debugf("Create finished\n")
	os.Exit(0)
	return nil
}

func (d *Driver) Start() error {
	//d.MockState = state.Running
	return nil
}

func (d *Driver) Stop() error {
	//d.MockState = state.Stopped
	return nil
}

func (d *Driver) Restart() error {
	//d.MockState = state.Running
	return nil
}

func (d *Driver) Kill() error {
	//d.MockState = state.Stopped
	return nil
}

func (d *Driver) Remove() error {
	return nil
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

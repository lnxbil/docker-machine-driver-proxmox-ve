package dockermachinedriverproxmoxve

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/resty.v1"

	sshrw "github.com/mosolovsa/go_cat_sshfilerw"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	"github.com/labstack/gommon/log"
)

const NO_VLAN = "No VLAN"

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

	VMID          string // VM ID only filled by create()
	GuestPassword string // password to log into the guest OS to copy the public key

	driverDebug bool // driver debugging
	restyDebug  bool // enable resty debugging

	NetBridge  string  // Net was defaulted to vmbr0, but should accept any other config i.e vmbr1
	NetModel   string  // Net Interface Model, [e1000, virtio, realtek, etc...]
	NetVlanTag int     // VLAN Tag -1 means NO Vlan
	Cores      string  // # of cores on each cpu socket
	Sockets    string  // # of cpu sockets
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
		mcnflag.StringFlag{
			Name:  "proxmox-guest-password",
			Usage: "Password to log in to the guest OS (default tcuser for boot2docker)",
			Value: "tcuser",
		},
		mcnflag.BoolFlag{
			Name:  "proxmox-resty-debug",
			Usage: "enables the resty debugging",
		},
		mcnflag.BoolFlag{
			Name:  "proxmox-driver-debug",
			Usage: "enables debugging in the driver",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_NET_BRIDGE",
			Name: "proxmox-net-bridge",
			Usage: "Assign Network Bridge, default to vmbr0",
			Value: "vmbr0",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_NET_MODEL",
			Name: "proxmox-net-model",
			Usage: "Net Interface model, default virtio",
			Value: "virtio",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_NET_VLANTAG",
			Name: "proxmox-net-vlantag",
			Usage: "Net VLAN Tag",
			Value: -1,
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_CPU_CORES",
			Name: "proxmox-cpu-cores",
			Usage: "# of CPU Cores on each CPU Socket",
			Value: "4",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOX_CPU_SOCKETS",
			Name: "proxmox-cpu-sockets",
			Usage: "# of CPU Sockets",
			Value: "1",
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
	d.GuestPassword = flags.String("proxmox-guest-password")

	d.driverDebug = flags.Bool("proxmox-driver-debug")
	d.restyDebug = flags.Bool("proxmox-resty-debug")
	if d.restyDebug {
		d.debug("enabling Resty debugging")
		resty.SetDebug(true)
	}

	d.NetBridge  = flags.String("proxmox-net-bridge")
	d.NetModel   = flags.String("proxmox-net-model")
	d.NetVlanTag = flags.Int("proxmox-net-vlantag")
	d.Sockets    = flags.Int("proxmox-cpu-sockets")
	d.Cores      = flags.Int("proxmox-cpu-cores")
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

	filename := "vm-" + d.VMID + "-disk-0"
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

	net := fmt.Sprintf("model=%s,bridge=%s", d.NetModel, d.NetBridge)
	if  d.NetVlanTag > 0 {
		net = fmt.Sprintf("%s,tag=%d", net, d.NetVlanTag)
	}

	npp := NodesNodeQemuPostParameter{
		VMID:      d.VMID,
		Agent:     "1",
		Autostart: "1",
		Memory:    d.Memory,
		Cores:     d.Cores,
		Sockets:   d.Sockets,
		Net0:      net, // Added to support bridge differnet from vmbr0 (vlan tag should be supported as well)
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
	return d.waitAndPrepareSSH()
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

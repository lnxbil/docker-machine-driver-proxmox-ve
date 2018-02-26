package dockermachinedriverproxmox

import (
	"fmt"
	"os"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	"github.com/labstack/gommon/log"
	"github.com/lnxbil/goproxmoxapi"
)

type Driver struct {
	*drivers.BaseDriver

	Host           string
	User           string
	Realm          string
	Password       string
	Boot2DockerURL string
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
			EnvVar: "PROXMOX_BOOT2DOCKER_FILE",
			Name:   "proxmox-boot2docker-file",
			Usage:  "Storage path",
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
	d.Boot2DockerURL = flags.String("proxmox-boot2docker-url")
	d.Host = flags.String("proxmox-host")
	d.User = flags.String("proxmox-user")
	d.Realm = flags.String("proxmox-realm")
	d.Password = flags.String("proxmox-password")

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
	c, err := goproxmoxapi.New(d.User, d.Password, d.Realm, d.Host)

	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	v, err := goproxmoxapi.GetVersion(c)
	log.Warn("Connected to version '" + v.Version + "'")

	log.Debugf("Create finished")
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

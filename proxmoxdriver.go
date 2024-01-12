package dockermachinedriverproxmoxve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	"github.com/labstack/gommon/log"

	"github.com/FreekingDean/proxmox-api-go/proxmox"
	"github.com/FreekingDean/proxmox-api-go/proxmox/access"
	"github.com/FreekingDean/proxmox-api-go/proxmox/cluster"
	"github.com/FreekingDean/proxmox-api-go/proxmox/nodes/qemu"
	"github.com/FreekingDean/proxmox-api-go/proxmox/nodes/qemu/agent"
	"github.com/FreekingDean/proxmox-api-go/proxmox/nodes/qemu/status"
	"github.com/FreekingDean/proxmox-api-go/proxmox/nodes/tasks"
	ignition "github.com/coreos/ignition/v2/config/v3_4/types"
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

	VMID          int    // VM ID only filled by create()
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

func (d *Driver) EnsureClient() (*proxmox.Client, error) {
	if d.client != nil {
		return d.client, nil
	}
	d.debugf("Create called")

	d.debugf("Connecting to %s as %s@%s with password '%s'", d.Host, d.User, d.Realm, d.Password)
	client := proxmox.NewClient(d.Host)
	a := access.New(client)
	ticket, err := a.CreateTicket(context.Background(), access.CreateTicketRequest{
		Username: d.User,
		Password: d.Password,
		Realm:    &d.Realm,
	})
	if err != nil {
		d.debugf("error retreiving ticket %s", err.Error())
		return nil, err
	}
	client.SetCookie(*ticket.Ticket)
	client.SetCsrf(*ticket.Csrfpreventiontoken)
	d.client = client
	return client, nil
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
		mcnflag.IntFlag{
			EnvVar: "PROXMOXVE_VM_MEMORY",
			Name:   "proxmoxve-vm-memory",
			Usage:  "memory in GB",
			Value:  8,
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_CPU_CORES",
			Name:   "proxmoxve-vm-cpu-cores",
			Usage:  "number of cpu cores",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_ISO_URL",
			Name:   "proxmoxve-vm-iso-url",
			Usage:  "ISO Download URL",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_ISO_FILENAME",
			Name:   "proxmoxve-vm-iso-filename",
			Usage:  "name of iso file post download",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "PROXMOXVE_VM_NET_BRIDGE",
			Name:   "proxmoxve-vm-net-bridge",
			Usage:  "bridge to attach network to",
			Value:  "vmbr0", // leave the flag default value blank to support the clone default behavior if not explicity set of 'use what is most appropriate'
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

	d.User = flags.String("proxmoxve-proxmox-user-name")
	d.Password = flags.String("proxmoxve-proxmox-user-password")
	d.Realm = flags.String("proxmoxve-proxmox-realm")
	d.Pool = flags.String("proxmoxve-proxmox-pool")

	// VM configuration
	d.DiskSize = flags.String("proxmoxve-vm-storage-size")
	d.Storage = flags.String("proxmoxve-vm-storage-path")
	d.Memory = flags.Int("proxmoxve-vm-memory")
	d.Memory *= 1024
	d.GuestUsername = "docker"
	d.ISOUrl = flags.String("proxmoxve-vm-iso-url")
	d.ISOFilename = flags.String("proxmoxve-vm-iso-filename")
	d.CPUCores = flags.String("proxmoxve-vm-cpu-cores")
	d.NetBridge = flags.String("proxmoxve-vm-net-bridge")
	d.NetVlanTag = flags.Int("proxmoxve-vm-net-tag")

	//Debug option
	d.driverDebug = flags.Bool("proxmoxve-debug-driver")

	return nil
}

// GetURL returns the URL for the target docker daemon
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
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
	if d.VMID < 1 {
		return state.Error, errors.New("invalid VMID")
	}

	c, err := d.EnsureClient()
	if err != nil {
		return state.Error, err
	}

	s := status.New(c)
	resp, err := s.VmStatusCurrent(context.Background(), status.VmStatusCurrentRequest{
		Node: d.Node,
		Vmid: d.VMID,
	})
	if resp.Status == status.Status_STOPPED {
		return state.Stopped, nil
	}
	if resp.Status == status.Status_RUNNING {
		return state.Running, nil
	}
	return state.Error, nil
}

// PreCreateCheck is called to enforce pre-creation steps
func (d *Driver) PreCreateCheck() error {
	_, err := d.EnsureClient()
	if err != nil {
		return err
	}

	if len(d.Storage) < 1 {
		d.Storage = "local"
	}

	if len(d.StorageType) < 1 {
		d.StorageType = "qcow2"
	}

	if len(d.NetBridge) < 1 {
		d.NetBridge = "vmbr0"
	}

	if d.StorageType != "raw" && d.StorageType != "qcow2" {
		return fmt.Errorf("storage type '%s' is not supported", d.StorageType)
	}
	if d.ProvisionStrategy != "clone" && d.ProvisionStrategy != "cdrom" {
		return fmt.Errorf("provision strategy '%s' is no supported", d.ProvisionStrategy)
	}

	return nil
}

// Create creates a new VM with storage
func (d *Driver) Create() error {
	c, err := d.EnsureClient()
	if err != nil {
		return err
	}

	cclient := cluster.New(c)
	id, err := cclient.Nextid(context.Background(), cluster.NextidRequest{})
	if err != nil {
		return err
	}
	tvalue := true

	key, err := d.generateKey()
	if err != nil {
		return err
	}
	cfg := &ignition.Config{
		Systemd: &ignition.Systemd{
			Units: []*ignition.Unit{
				&ignition.Unit{
					Name:    "rpm-ostree-install-qemu-guest-agent.service",
					Enabled: &tvalue,
					Content: `
[Unit]
Description=Layer qemu-guest-agent with rpm-ostree
Wants=network-online.target
After=network-online.target
Before=zincati.service
ConditionPathExists=!/var/lib/%N.stamp

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/rpm-ostree install --apply-live --allow-inactive qemu-guest-agent && systemctl --now enable qemu-guest-agent
ExecStart=/bin/touch /var/lib/%N.stamp

[Install]
WantedBy=multi-user.target
`,
				},
			},
		},
		Passwd: &ignition.Passwd{
			Users: []*ignition.User{
				&ignition.PasswdUser{
					Name: "docker",
					SSHAuthorizedKeys: []ignition.SSHAuthorizedKey{
						ignition.SSHAuthorizedKey(key),
					},
				},
			},
		},
	}

	cfgStr, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	storage.DownloadUrl(context.Background(), storage.DownloadUrlRequest{
		ContentType: "iso",
		Filename:    d.IsoFilename,
		Storage:     d.Storage,
		Node:        d.Node,
		Url:         d.ISOUrl,
	})

	d.debugf("Next ID is '%s'", id)
	d.VMID = id
	req := qemu.CreateRequest{
		Vmid:   d.VMID,
		Args:   fmt.Sprintf("-fw_cfg %s", strings.Replace(cfgStr, ",", ",,")),
		Name:   d.GetMachineName(),
		Node:   d.Node,
		Memory: d.Memory,
		Cores:  d.CPUCores,
		Pool:   proxmox.PVEString(d.Pool),
		Nets: &qemu.Nets{
			&qemu.Net{
				Model:  qermu.NetModel_VIRTIO,
				Bridge: d.Bridge,
				Tag:    d.Tag,
			},
		},
		Agent: &qemu.Agent{
			Enabled: *proxmox.PVEBool(plan.GuestAgent.ValueBool()),
		},
		Serials: &qemu.Serials{"socket"},
		Ides: &qemu.Ides{
			&qemu.Ide{
				File:  fmt.Sprintf("%s:iso/%s", d.Storage, d.IsoFilename),
				Media: qemu.IdeMedia_CDROM,
			},
		},
		Scsis: &qemu.Scsis{
			&qemu.Scsi{
				File: fmt.Sprintf("%s:%d", d.Storage, d.DiskSize),
			},
		},
	}
	_, err := qemu.Create(context.Background(), req)
	if err != nil {
		return err
	}
	dangling := true
	defer func() {
		if dangling {
			d.Remove()
		}
	}()

	// start the VM
	err = d.Start()
	if err != nil {
		return err
	}

	// let VM start a settle a little
	d.debugf("waiting for VM to start, wait 10 seconds")
	time.Sleep(10 * time.Second)

	// wait for network to come up
	err = d.waitForNetwork()
	if err != nil {
		return err
	}
	dangling = false
	return nil
}

func (d *Driver) checkIP() (string, error) {
	d.debugf("checking for IP address")
	c, err := d.EnsureClient()
	if err != nil {
		return err
	}
	a := agent.New(c)
	resp, err := a.Create(context.Background(), agent.CreateRequest{
		Command: "network-get-interfaces",
		Node:    d.Node,
		Vmid:    d.VMID,
	})

	for _, nic := range resp["data"]["result"] {
		if nic["name"] != "lo" {
			for _, ip := range nic["ip-addresses"] {
				if ip["ip-address-type"] == "ipv4" && ip["ip-address"] != "127.0.0.1" {
					return ip["ip-address"], nil
				}
			}
		}
	}
	return "", nil
}

func (d *Driver) waitForNetwork() error {
	// attempt over 5 minutes
	// time for startup, qemu install, and network to come online
	for i := 0; i < 60; i++ {
		ip, err := d.checkIP()
		if err != nil {
			return err
		}
		if ip != "" {
			d.IPAddress = ip
			return nil
		}
		d.debugf("waiting for VM network to start")
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("failed waiting for IP")
}

// Start starts the VM
func (d *Driver) Start() error {
	if d.VMID < 1 {
		return errors.New("invalid VMID")
	}

	c, err := d.EnsureClient()
	if err != nil {
		return err
	}

	s := status.New(c)
	taskID, err := s.VmStart(context.Background(), status.VmStartRequest{
		Node: d.Node,
		Vmid: d.VMID,
	})
	if err != nil {
		return err
	}

	return d.waitForTaskToComplete(taskID, 2*time.Minute)
}

func (d *Driver) waitForTaskToComplete(taskId string, dur time.Duration) error {
	c, err := d.EnsureClient()
	if err != nil {
		return err
	}

	t := tasks.New(c)

	endTime := time.Now().Add(dur)
	for !time.Now().After(endTime) {
		resp, err := t.ReadTaskStatus(
			context.Background(),
			tasks.ReadTaskStatusRequest{
				Node: node,
				Upid: upid,
			},
		)
		if err != nil {
			return err
		}
		if resp.Status != "running" {
			if resp.ExitStatus != "OK" {
				return fmt.Errorf("task failed")
			}
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timed out waiting for task")
}

// Stop stopps the VM
func (d *Driver) Stop() error {
	if d.VMID < 1 {
		return errors.New("invalid VMID")
	}

	c, err := d.EnsureClient()
	if err != nil {
		return err
	}

	s := status.New(c)
	taskID, err := s.VmShutdown(context.Background(), status.VmShutdownRequest{
		Node: d.Node,
		Vmid: d.VMID,
	})
	if err != nil {
		return err
	}

	return d.waitForTaskToComplete(taskID, 10*time.Minute)
}

// Restart restarts the VM
func (d *Driver) Restart() error {
	if d.VMID < 1 {
		return errors.New("invalid VMID")
	}

	c, err := d.EnsureClient()
	if err != nil {
		return err
	}

	s := status.New(c)
	taskID, err := s.VmReboot(context.Background(), status.VmRebootRequest{
		Node: d.Node,
		Vmid: d.VMID,
	})
	if err != nil {
		return err
	}

	return d.waitForTaskToComplete(taskID, 10*time.Minute)
}

// Kill the VM immediately
func (d *Driver) Kill() error {
	if d.VMID < 1 {
		return errors.New("invalid VMID")
	}

	c, err := d.EnsureClient()
	if err != nil {
		return err
	}

	s := status.New(c)
	taskID, err := s.VmStop(context.Background(), status.VmStopRequest{
		Node: d.Node,
		Vmid: d.VMID,
	})
	if err != nil {
		return err
	}

	return d.waitForTaskToComplete(taskID, 10*time.Minute)
}

// Remove removes the VM
func (d *Driver) Remove() error {
	if d.VMID < 1 {
		return nil
	}
	// force shut down VM before invoking delete
	err = d.Kill()
	if err != nil {
		return err
	}

	c, err := d.EnsureClient()
	if err != nil {
		return err
	}
	q := qemu.New(c)

	taskId, err := q.Delete(context.Background(), qemu.DeleteRequest{
		Vmid:                     d.VMID,
		Node:                     d.Node,
		DestroyUnreferencedDisks: proxmox.PVEBool(true),
		Purge:                    proxmox.PVEBool(true),
	})
	if err != nil {
		return err
	}
	return d.waitForTaskToComplete(taskID, 10*time.Minute)
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

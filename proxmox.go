package dockermachinedriverproxmoxve

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	resty "gopkg.in/resty.v1"
)

// ProxmoxVE open api connection representation
type ProxmoxVE struct {
	// connection parameters
	Username string // root
	password string // must be given
	Realm    string // pam
	Host     string
	Port     int // default 8006

	// not so imported internal stuff
	Node                string // if not present, use first node present
	Prefix              string // if PVE is proxied, this is the added prefix
	CSRFPreventionToken string // filled by the framework
	Ticket              string // filled by the framework

	Version string // ProxmoxVE version of the connected host

	client *resty.Client // resty client
}

// GetProxmoxVEConnectionByValues is a wrapper for GetProxmoxVEConnection with strings as input
func GetProxmoxVEConnectionByValues(username string, password string, realm string, hostname string) (*ProxmoxVE, error) {
	return GetProxmoxVEConnection(&ProxmoxVE{
		Username: username,
		password: password,
		Realm:    realm,
		Host:     hostname,
	})
}

// GetProxmoxVEConnection retrievs a connection to a Proxmox VE host
func GetProxmoxVEConnection(data *ProxmoxVE) (*ProxmoxVE, error) {
	if data.Port == 0 {
		data.Port = 8006
	}

	if len(data.password) == 0 {
		return data, fmt.Errorf("You have to provide a password")
	}

	if len(data.Username) == 0 {
		data.Username = "root"
	}
	if len(data.Realm) == 0 {
		data.Realm = "pam"
	}

	data.client = resty.New()

	//data.client.SetDebug(true)
	data.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	//data.client.SetTimeout(time.Duration(3 * time.Second))

	outp, err := data.accessTicketPost(&AccessTicketPostParameter{
		Username: data.Username,
		Realm:    data.Realm,
		Password: data.password,
	})

	if err != nil {
		return data, err
	}

	if outp.Csrfpreventiontoken == "" {
		return nil, fmt.Errorf("Could not extract CSRFPreventionToken")
	}

	data.CSRFPreventionToken = outp.Csrfpreventiontoken
	data.client.SetHeader("CSRFPreventionToken", outp.Csrfpreventiontoken)
	data.client.SetCookie(&http.Cookie{
		Name:  "PVEAuthCookie",
		Value: outp.Ticket,
	})
	data.Ticket = outp.Ticket

	ver, err := data.versionGet()
	if err != nil {
		return data, err
	}

	data.Version = ver.Version

	return data, nil
}

func (p ProxmoxVE) getURL(str string) string {
	return fmt.Sprintf("https://%s:%d/%sapi2/json%s", p.Host, p.Port, p.Prefix, str)
}

// idea taken from https://gist.github.com/tonyhb/5819315
func (p ProxmoxVE) structToStringMap(i interface{}) map[string]string {
	retval := make(map[string]string, 0)
	if i == nil {
		return retval
	}
	iVal := reflect.ValueOf(i).Elem()
	typ := iVal.Type()
	for i := 0; i < iVal.NumField(); i++ {
		f := iVal.Field(i)
		// You ca use tags here...
		// tag := typ.Field(i).Tag.Get("tagname")
		// Convert each type into a string for the url.Values string map
		var v string
		switch f.Interface().(type) {
		case int, int8, int16, int32, int64:
			v = strconv.FormatInt(f.Int(), 10)
		case uint, uint8, uint16, uint32, uint64:
			v = strconv.FormatUint(f.Uint(), 10)
		case float32:
			v = strconv.FormatFloat(f.Float(), 'f', 4, 32)
		case float64:
			v = strconv.FormatFloat(f.Float(), 'f', 4, 64)
		case []byte:
			v = string(f.Bytes())
		case string:
			v = f.String()
		case bool:
			// map to Proxmox VE API boolean, which is int with 1 for true and 0 for false
			if f.Bool() {
				v = "1"
			} else {
				v = "0"
			}
		}
		if len(v) > 0 {
			retval[strings.ToLower(typ.Field(i).Name)] = v
		}
	}
	return retval
}

func (p ProxmoxVE) post(input interface{}, output interface{}, path string) error {
	return p.runMethod("post", input, output, path)
}

func (p ProxmoxVE) get(input interface{}, output interface{}, path string) error {
	return p.runMethod("get", input, output, path)
}

func (p ProxmoxVE) put(input interface{}, output interface{}, path string) error {
	return p.runMethod("put", input, output, path)
}

func (p ProxmoxVE) delete(input interface{}, output interface{}, path string) error {
	return p.runMethod("delete", input, output, path)
}

func (p ProxmoxVE) runMethod(method string, input interface{}, output interface{}, path string) error {
	var response *resty.Response
	var err error

	switch method {
	case "get":
		response, err = p.client.R().SetQueryParams(p.structToStringMap(input)).Get(p.getURL(path))
	case "post":
		response, err = p.client.R().SetQueryParams(p.structToStringMap(input)).Post(p.getURL(path))
	case "put":
		response, err = p.client.R().SetQueryParams(p.structToStringMap(input)).Put(p.getURL(path))
	case "delete":
		response, err = p.client.R().SetQueryParams(p.structToStringMap(input)).Delete(p.getURL(path))
	default:
		return fmt.Errorf("method '%s' not known", method)
	}

	if err != nil {
		return err
	}
	code := response.StatusCode()
	if code < 200 || code > 300 {
		return fmt.Errorf("status code was '%d' and error is\n%s", code, response.Status())
	}

	if output == nil {
		return nil
	}

	var f map[string]interface{}

	err = json.Unmarshal([]byte(response.String()), &f)
	if err != nil {
		return err
	}
	zz, err := json.Marshal(f["data"])
	if err != nil {
		return err
	}

	err = json.Unmarshal(zz, &output)

	return err
}

// AccessTicketPostParameter represents the input data for /access/ticket
// Original Description:
// Create or verify authentication ticket.
type AccessTicketPostParameter struct {
	Privs    string // optional
	Realm    string // optional
	Username string
	OTP      string // optional
	Password string
	Path     string // optional
}

// AccessTicketReturnParameter represents the returned data from /access/ticket
// Original Description:
// Create or verify authentication ticket.
type AccessTicketReturnParameter struct {
	Username            string
	Csrfpreventiontoken string
	Ticket              string
}

// AccessTicketPost access the API
// Create or verify authentication ticket.
func (p ProxmoxVE) accessTicketPost(input *AccessTicketPostParameter) (*AccessTicketReturnParameter, error) {
	path := "/access/ticket"
	outp := AccessTicketReturnParameter{}
	err := p.post(input, &outp, path)
	return &outp, err
}

// VersionReturnParameter represents the returned data from /version
// Original Description:
// API version details. The result also includes the global datacenter confguration.
type VersionReturnParameter struct {
	RepoID  string
	Version string
	Release string
}

// VersionGet access the API
// API version details. The result also includes the global datacenter confguration.
func (p ProxmoxVE) versionGet() (*VersionReturnParameter, error) {
	path := "/version"
	outp := VersionReturnParameter{}
	err := p.get(nil, &outp, path)
	return &outp, err
}

// NodesNodeStorageStorageContentPostParameter represents the input data for /nodes/{node}/storage/{storage}/content
// Original Description:
// Allocate disk images.
type NodesNodeStorageStorageContentPostParameter struct {
	Filename string // The name of the file to create.
	Size     string // Size in kilobyte (1024 bytes). Optional suffixes 'M' (megabyte, 1024K) and 'G' (gigabyte, 1024M)
	VMID     string // Specify owner VM
	Format   string // optional,
}

// NodesNodeStorageStorageContentPost access the API
// Allocate disk images.
func (p ProxmoxVE) NodesNodeStorageStorageContentPost(node string, storage string, input *NodesNodeStorageStorageContentPostParameter) error {
	path := fmt.Sprintf("/nodes/%s/storage/%s/content", node, storage)
	err := p.post(input, nil, path)
	return err
}

// ClusterNextIDGet Get next free VMID. If you pass an VMID it will raise an error if the ID is already used.
func (p ProxmoxVE) ClusterNextIDGet(id int) (vmid string, err error) {
	path := "/cluster/nextid"
	if id == 0 {
		err = p.get(nil, &vmid, path)
	} else {
		err = p.get(id, &vmid, path)
	}
	return vmid, err
}

// NodesNodeQemuPostParameter represents the input data for /nodes/{node}/qemu
// Original Description:
// Create or restore a virtual machine.
type NodesNodeQemuPostParameter struct {
	VMID      string // The (unique) ID of the VM.
	Memory    int    // optional, Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
	Autostart string // optional, Automatic restart after crash (currently ignored).
	Agent     string // optional, Enable/disable Qemu GuestAgent.
	Net0      string
	Name      string // optional, Set a name for the VM. Only used on the configuration web interface.
	SCSI0     string // optional, Use volume as VIRTIO hard disk (n is 0 to 15).
	Ostype    string // optional, Specify guest operating system.
	KVM       string // optional, Enable/disable KVM hardware virtualization.
	Cores     string // optional, The number of cores per socket.
	Cdrom     string // optional, This is an alias for option -ide2
}

type nNodesNodeQemuPostParameter struct {
	VMID            string   // The (unique) ID of the VM.
	Acpi            bool     // optional, Enable/disable ACPI.
	Agent           string   // optional, Enable/disable Qemu GuestAgent.
	Archive         string   // optional, The backup file.
	Args            string   // optional, Arbitrary arguments passed to kvm.
	Autostart       string   // optional, Automatic restart after crash (currently ignored).
	Balloon         int      // optional, Amount of target RAM for the VM in MB. Using zero disables the ballon driver.
	Bios            string   // optional, Select BIOS implementation.
	Boot            string   // optional, Boot on floppy (a), hard disk (c), CD-ROM (d), or network (n).
	Bootdisk        string   // optional, Enable booting from specified disk.
	Cdrom           string   // optional, This is an alias for option -ide2
	Cores           string   // optional, The number of cores per socket.
	CPU             string   // optional, Emulated CPU type.
	Cpulimit        int      // optional, Limit of CPU usage.
	Cpuunits        int      // optional, CPU weight for a VM.
	Description     string   // optional, Description for the VM. Only used on the configuration web interface. This is saved as comment inside the configuration file.
	Force           bool     // optional, Allow to overwrite existing VM.
	Freeze          bool     // optional, Freeze CPU at startup (use 'c' monitor command to start execution).
	Hostpci         []string // optional, Map host PCI devices into guest.
	Hotplug         string   // optional, Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Value '1' is an alias for the default 'network,disk,usb'.
	Hugepages       string   // optional, Enable/disable hugepages memory.
	IDE             []string // optional, Use volume as IDE hard disk or CD-ROM (n is 0 to 3).
	Keyboard        string   // optional, Keybord layout for vnc server. Default is read from the '/etc/pve/datacenter.conf' configuration file.
	KVM             bool     // optional, Enable/disable KVM hardware virtualization.
	Localtime       bool     // optional, Set the real time clock to local time. This is enabled by default if ostype indicates a Microsoft OS.
	Lock            string   // optional, Lock/unlock the VM.
	Machine         string   // optional, Specific the Qemu machine type.
	Memory          string   // optional, Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
	MigrateDowntime int      // optional, Set maximum tolerated downtime (in seconds) for migrations.
	MigrateSpeed    int      // optional, Set maximum speed (in MB/s) for migrations. Value 0 is no limit.
	Name            string   // optional, Set a name for the VM. Only used on the configuration web interface.
	Net0            string
	//NET             []string // optional, Specify network devices.
	// numa is defined more than once, we ignore the bool parameter
	//Numa bool // optional, Enable/disable NUMA.
	Numa           []string // optional, NUMA topology.
	Onboot         bool     // optional, Specifies whether a VM will be started during system bootup.
	Ostype         string   // optional, Specify guest operating system.
	Parallel       []string // optional, Map host parallel devices (n is 0 to 2).
	Pool           string   // optional, Add the VM to the specified pool.
	Protection     bool     // optional, Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
	Reboot         bool     // optional, Allow reboot. If set to '0' the VM exit on reboot.
	Sata           []string // optional, Use volume as SATA hard disk or CD-ROM (n is 0 to 5).
	Scsi           []string // optional, Use volume as SCSI hard disk or CD-ROM (n is 0 to 13).
	Scsihw         string   // optional, SCSI controller model
	Serial         []string // optional, Create a serial device inside the VM (n is 0 to 3)
	Shares         int      // optional, Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning
	Smbios1        string   // optional, Specify SMBIOS type 1 fields.
	SMP            int      // optional, The number of CPUs. Please use option -sockets instead.
	Sockets        string   // optional, The number of CPU sockets.
	Startdate      string   // optional, Set the initial date of the real time clock. Valid format for date are: 'now' or '2006-06-17T16:01:21' or '2006-06-17'.
	Startup        string   // optional, Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
	Storage        string   // optional, Default storage.
	Tablet         bool     // optional, Enable/disable the USB tablet device.
	TDF            bool     // optional, Enable/disable time drift fix.
	Template       bool     // optional, Enable/disable Template.
	Unique         bool     // optional, Assign a unique random ethernet address.
	Unused         []string // optional, Reference to unused volumes. This is used internally, and should not be modified manually.
	USB            []string // optional, Configure an USB device (n is 0 to 4).
	Vcpus          int      // optional, Number of hotplugged vcpus.
	VGA            string   // optional, Select the VGA type.
	Virtio         []string // optional, Use volume as VIRTIO hard disk (n is 0 to 15).
	VMstatestorage string   // optional, Default storage for VM state volumes/files.
	Watchdog       string   // optional, Create a virtual hardware watchdog device.
}

// NodesNodeQemuPost access the API
// Create or restore a virtual machine.
func (p ProxmoxVE) NodesNodeQemuPost(node string, input *NodesNodeQemuPostParameter) error {
	path := fmt.Sprintf("/nodes/%s/qemu", node)
	err := p.post(input, nil, path)
	return err
}

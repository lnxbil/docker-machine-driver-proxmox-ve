package main

import (
	proxmox "github.com/lnxbil/docker-machine-driver-proxmox-ve"

	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(proxmox.NewDriver("default", ""))
}

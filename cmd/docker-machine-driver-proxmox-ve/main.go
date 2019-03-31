package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	proxmox "github.com/mhermosi/docker-machine-driver-proxmox-ve"
)

func main() {
	plugin.RegisterDriver(proxmox.NewDriver("default", ""))
}

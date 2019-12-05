package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	proxmoxve "../.."
)

func main() {
	plugin.RegisterDriver(proxmoxve.NewDriver("default", ""))
}

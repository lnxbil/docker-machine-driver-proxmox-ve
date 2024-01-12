package ssh

import (
	"fmt"
	"os"

	mcnssh "github.com/docker/machine/libmachine/ssh"
)

func (d *Driver) generateKey() (string, error) {
	// create and save a new SSH key pair
	d.debug("creating new ssh keypair")
	if err := mcnssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return "", fmt.Errorf("could not generate ssh key: %w", err)
	}
	buf, err := os.ReadFile(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return "", fmt.Errorf("could not read ssh public key: %w", err)
	}
	return string(buf), nil
}

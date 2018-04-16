package dockermachinedriverproxmoxve_test

import (
	"strconv"
	"testing"

	dockermachinedriverproxmoxve "github.com/lnxbil/docker-machine-driver-proxmox-ve"
)

func TestSuccessfulConnection(t *testing.T) {
	api := EstablishConnection(t)

	val, err := strconv.ParseFloat(api.Version, 32)
	if err != nil {
		t.Error("Error occured")
		t.Error(err)
	}
	if val < 5.0 {
		t.Errorf("API version should be '5.x', but was '%f'", val)
	}
}
func TestWrongPass(t *testing.T) {
	username, _, realm, host := GetProxmoxAccess()
	_, err := dockermachinedriverproxmoxve.GetProxmoxVEConnectionByValues(username, "wrong_password", realm, host)
	if err == nil {
		t.Log(err)
		t.Error()
	}
}
func TestWrongUser(t *testing.T) {
	_, password, realm, host := GetProxmoxAccess()
	_, err := dockermachinedriverproxmoxve.GetProxmoxVEConnectionByValues("root", password, realm, host)
	if err == nil {
		t.Log(err)
		t.Error()
	}
}

func TestEmptyPass(t *testing.T) {
	username, _, realm, host := GetProxmoxAccess()
	_, err := dockermachinedriverproxmoxve.GetProxmoxVEConnectionByValues(username, "", realm, host)
	if err != nil && err.Error() != "You have to provide a password" {
		t.Log(err)
		t.Error()
	}
}

func TestWrongHost(t *testing.T) {
	username, password, realm, _ := GetProxmoxAccess()
	_, err := dockermachinedriverproxmoxve.GetProxmoxVEConnectionByValues(username, password, realm, "127.0.0.1")
	if err == nil {
		t.Log(err)
		t.Error()
	}
}

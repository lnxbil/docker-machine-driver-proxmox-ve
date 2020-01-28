ifndef
	DRIVER_NAME = proxmoxve
endif

all:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X 'github.com/lnxbil/docker-machine-driver-proxmox-ve.dName=$DRIVER_NAME'" -o docker-machine-driver-$DRIVER_NAME.linux-amd64
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X 'github.com/lnxbil/docker-machine-driver-proxmox-ve.dName=$DRIVER_NAME'" -o docker-machine-driver-$DRIVER_NAME.macos-amd64
	
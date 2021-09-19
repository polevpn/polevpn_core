package core

import (
	"os"

	"github.com/polevpn/water"
)

type TunDevice struct {
	ifce *water.Interface
}

func NewTunDevice() (*TunDevice, error) {
	device := &TunDevice{}
	config := water.Config{
		DeviceType: water.TUN,
	}
	ifce, err := water.New(config)
	if err != nil {
		return nil, err
	}
	device.ifce = ifce
	return device, nil
}

func AttachTunDevice(fd int) *TunDevice {
	device := &TunDevice{}
	device.ifce = water.NewInterface("tun", os.NewFile(uintptr(fd), "tun"), false)
	return device
}

func (td *TunDevice) GetInterface() *water.Interface {
	return td.ifce
}

func (td *TunDevice) Close() error {
	return td.ifce.Close()
}

package core

import (
	"io"
	"os"

	"github.com/polevpn/water"
)

type TunDevice struct {
	ifce *water.Interface
}

type IosTunFile struct {
	io.ReadWriteCloser
	tun    *os.File
	header [4]byte
}

func (itf *IosTunFile) Read(p []byte) (int, error) {

	buf := make([]byte, len(p)+4)

	n, err := itf.tun.Read(buf)

	if err != nil {
		return n, err
	}

	copy(itf.header[:], buf[0:4])
	copy(p, buf[4:n])

	return n - 4, err

}

func (itf *IosTunFile) Write(p []byte) (int, error) {

	buf := make([]byte, len(p)+4)

	copy(buf[:4], itf.header[:])
	copy(buf[4:], p)

	_, err := itf.tun.Write(buf)

	return len(p), err
}

func (itf *IosTunFile) Close() error {

	return itf.tun.Close()
}

func NewIosTunFile(tun *os.File) *IosTunFile {
	itf := &IosTunFile{tun: tun}
	return itf
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

func AttachTunDeviceIos(fd int) *TunDevice {
	device := &TunDevice{}
	device.ifce = water.NewInterface("tun", NewIosTunFile(os.NewFile(uintptr(fd), "tun")), false)
	return device
}

func (td *TunDevice) GetInterface() *water.Interface {
	return td.ifce
}

func (td *TunDevice) Close() error {
	return td.ifce.Close()
}

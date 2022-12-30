package core

import "net/http"

type Conn interface {
	Connect(endpoint string, user string, pwd string, ip string, sni string, skipVerifySSL bool, deviceType string, deviceId string, header http.Header) error
	Close(flag bool) error
	String() string
	IsClosed() bool
	SetHandler(cmd uint16, handler func(PolePacket, Conn))
	Send(pkt []byte)
	StartProcess()
	GetUpDownBytes() (uint64, uint64)
}

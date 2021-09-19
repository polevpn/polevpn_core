package core

type Conn interface {
	SetLocalIP(string)
	Connect(endpoint string, user string, pwd string, ip string, sni string, skipVerifySSL bool) error
	Close(flag bool) error
	String() string
	IsClosed() bool
	SetHandler(cmd uint16, handler func(PolePacket, Conn))
	Send(pkt []byte)
	StartProcess()
}

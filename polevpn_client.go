package core

import (
	"github.com/polevpn/anyvalue"
	"github.com/polevpn/elog"
)

const (
	POLE_CLIENT_INIT        = 0
	POLE_CLIENT_RUNING      = 1
	POLE_CLIENT_CLOSED      = 2
	POLE_CLIENT_RECONNETING = 3
)

const (
	VERSION_IP_V4                = 4
	VERSION_IP_V6                = 6
	TUN_DEVICE_CH_WRITE_SIZE     = 200
	HEART_BEAT_INTERVAL          = 10
	RECONNECT_TIMES              = 600000000
	RECONNECT_INTERVAL           = 5
	WEBSOCKET_NO_HEARTBEAT_TIMES = 2
)

const (
	CLIENT_EVENT_ADDRESS_ALLOCED = 1
	CLIENT_EVENT_RECONNECTING    = 2
	CLIENT_EVENT_STARTED         = 3
	CLIENT_EVENT_STOPPED         = 4
	CLIENT_EVENT_ERROR           = 5
	CLIENT_EVENT_RECONNECTED     = 6
)

const (
	ERROR_LOGIN   = "login"
	ERROR_NETWORK = "network"
	ERROR_UNKNOWN = "unknown"
	ERROR_IO      = "io"
	ERROR_ALLOC   = "alloc"
)

var plog *elog.EasyLogger

func init() {
	if plog == nil {
		plog = elog.GetLogger()
	}
}

func SetLogger(elog *elog.EasyLogger) {
	plog = elog
}

type PoleVpnClient interface {
	AttachTunDevice(*TunDevice)
	SetEventHandler(func(int, PoleVpnClient, *anyvalue.AnyValue))
	GetUpDownBytes() (uint64, uint64)
	GetRemoteIP() string
	SetLocalIP(ip string)
	Start(string, string, string, string, bool, string, string) error
	CloseConnect(flag bool)
	WaitStop()
	IsStoped() bool
	Stop()
}

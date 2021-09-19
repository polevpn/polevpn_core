package core

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

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
	TUN_DEVICE_CH_WRITE_SIZE     = 2048
	HEART_BEAT_INTERVAL          = 10
	RECONNECT_TIMES              = 60
	RECONNECT_INTERVAL           = 5
	WEBSOCKET_NO_HEARTBEAT_TIMES = 3
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

type PoleVpnClient struct {
	tunio             *TunIO
	conn              Conn
	state             int
	mutex             *sync.Mutex
	endpoint          string
	user              string
	pwd               string
	sni               string
	allocip           string
	localip           string
	lasttimeHeartbeat time.Time
	reconnecting      bool
	wg                *sync.WaitGroup
	mode              bool
	device            *TunDevice
	handler           func(int, *PoleVpnClient, *anyvalue.AnyValue)
	host              string
}

func init() {
	if plog == nil {
		plog = elog.GetLogger()
	}
}

func SetLogger(elog *elog.EasyLogger) {
	plog = elog
}

func NewPoleVpnClient() (*PoleVpnClient, error) {

	client := &PoleVpnClient{
		conn:  nil,
		state: POLE_CLIENT_INIT,
		mutex: &sync.Mutex{},
		wg:    &sync.WaitGroup{},
	}
	return client, nil
}

func (pc *PoleVpnClient) AttachTunDevice(device *TunDevice) {
	pc.device = device
	if pc.tunio != nil {
		pc.tunio.Close()
	}

	pc.tunio = NewTunIO(TUN_DEVICE_CH_WRITE_SIZE)
	pc.tunio.SetPacketHandler(pc.handleTunPacket)
	pc.tunio.AttachDevice(device)
	pc.tunio.StartProcess()
}

func (pc *PoleVpnClient) SetEventHandler(handler func(int, *PoleVpnClient, *anyvalue.AnyValue)) {
	pc.handler = handler
}

func (pc *PoleVpnClient) SetRouteMode(mode bool) {
	pc.mode = mode
}

func (pc *PoleVpnClient) Start(endpoint string, user string, pwd string, sni string) error {

	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state != POLE_CLIENT_INIT {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "client stoped or not init").Set("type", ERROR_UNKNOWN))
		}
		return errors.New("client stoped or not init")
	}

	pc.user = user
	pc.pwd = pwd
	pc.sni = sni
	var err error

	u, _ := url.Parse(endpoint)

	pc.host = u.Host

	if strings.HasPrefix(endpoint, "wss://") {
		pc.conn = NewWebSocketConn()
	} else if strings.HasPrefix(endpoint, "quic://") {
		endpoint = strings.Replace(endpoint, "quic://", "https://", -1)
		pc.conn = NewHttp3Conn()
	} else {
		return errors.New("invalid protocol")
	}

	pc.conn.SetLocalIP(pc.localip)
	pc.endpoint = endpoint

	err = pc.conn.Connect(endpoint, user, pwd, "", sni)
	if err != nil {
		if err == ErrLoginVerify {
			if pc.handler != nil {
				pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "user or password invalid").Set("type", ERROR_LOGIN))
			}
		} else {
			if pc.handler != nil {
				pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "connet fail,"+err.Error()).Set("type", ERROR_NETWORK))
			}
		}
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return err
	}

	pc.conn.SetHandler(CMD_ALLOC_IPADDR, pc.handlerAllocAdressRespose)
	pc.conn.SetHandler(CMD_S2C_IPDATA, pc.handlerIPDataResponse)
	pc.conn.SetHandler(CMD_CLIENT_CLOSED, pc.handlerConnCloseEvent)
	pc.conn.SetHandler(CMD_HEART_BEAT, pc.handlerHeartBeatRespose)
	pc.conn.StartProcess()
	pc.AskAllocIPAddress()

	pc.lasttimeHeartbeat = time.Now()
	go pc.HeartBeat()
	pc.state = POLE_CLIENT_RUNING
	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_STARTED, pc, nil)
	}
	pc.wg.Add(1)
	return nil
}

func (pc *PoleVpnClient) SetLocalIP(ip string) {
	if pc.conn != nil {
		pc.conn.SetLocalIP(ip)
	}
	pc.localip = ip
}

func (pc *PoleVpnClient) CloseConnect(flag bool) {
	pc.conn.Close(flag)
}

func (pc *PoleVpnClient) WaitStop() {
	pc.wg.Wait()
}

func (pc *PoleVpnClient) handleTunPacket(pkt []byte) {

	if pkt == nil {
		pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("type", ERROR_IO).Set("error", "tun device close exception"))
		pc.Stop()
		return
	}
	version := pkt[0]
	version = version >> 4

	if version != VERSION_IP_V4 {
		return
	}

	pc.sendIPPacketToRemoteConn(pkt)
}

func (pc *PoleVpnClient) sendIPPacketToRemoteConn(pkt []byte) {

	if pc.conn != nil {
		buf := make([]byte, POLE_PACKET_HEADER_LEN+len(pkt))
		copy(buf[POLE_PACKET_HEADER_LEN:], pkt)
		polepkt := PolePacket(buf)
		polepkt.SetCmd(CMD_C2S_IPDATA)
		polepkt.SetLen(uint16(len(buf)))
		pc.conn.Send(polepkt)
	} else {
		plog.Error("remote ws conn haven't set")
	}

}

func (pc *PoleVpnClient) AskAllocIPAddress() {
	buf := make([]byte, POLE_PACKET_HEADER_LEN)
	PolePacket(buf).SetCmd(CMD_ALLOC_IPADDR)
	PolePacket(buf).SetLen(POLE_PACKET_HEADER_LEN)
	pc.conn.Send(buf)
}

func (pc *PoleVpnClient) handlerAllocAdressRespose(pkt PolePacket, conn Conn) {

	av, err := anyvalue.NewFromJson(pkt.Payload())

	if err != nil {
		plog.Error("alloc address av decode fail,", err)
		pc.Stop()
		return
	}

	ip1 := av.Get("ip").AsStr()

	if ip1 == "" {
		plog.Error("alloc ip fail,stop client")
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "alloc ip fail").Set("type", ERROR_ALLOC))
		}
		pc.Stop()
		return
	}

	pc.allocip = ip1

	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_ADDRESS_ALLOCED, pc, av)
	}
}

func (pc *PoleVpnClient) handlerHeartBeatRespose(pkt PolePacket, conn Conn) {
	plog.Debug("received heartbeat")
	pc.lasttimeHeartbeat = time.Now()
}

func (pc *PoleVpnClient) handlerIPDataResponse(pkt PolePacket, conn Conn) {
	pc.tunio.Enqueue(pkt[POLE_PACKET_HEADER_LEN:])
}

func (pc *PoleVpnClient) handlerConnCloseEvent(pkt PolePacket, conn Conn) {
	plog.Info("client closed,start reconnect")
	pc.reconnect()
}

func (pc *PoleVpnClient) reconnect() {

	if pc.reconnecting {
		plog.Info("conn is reconnecting")
		return
	}

	pc.reconnecting = true
	pc.state = POLE_CLIENT_RECONNETING

	success := false
	for i := 0; i < RECONNECT_TIMES; i++ {

		if pc.state == POLE_CLIENT_CLOSED {
			break
		}

		plog.Info("reconnecting")
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_RECONNECTING, pc, nil)
		}
		err := pc.conn.Connect(pc.endpoint, pc.user, pc.pwd, pc.allocip, pc.sni)

		if pc.state == POLE_CLIENT_CLOSED {
			break
		}

		if err != nil {
			if err == ErrNetwork {
				if i < 10 {
					time.Sleep(time.Second)
					plog.Error("retry 1 seconds later")
				} else {
					time.Sleep(time.Second * RECONNECT_INTERVAL)
					plog.Error("retry " + strconv.Itoa(RECONNECT_INTERVAL) + " seconds later")
				}
				continue
			} else if err == ErrIPNotExist {
				plog.Error("ip address expired,reconnect and request new")
				pc.allocip = ""
			} else {
				plog.Error("server refuse connect")
				break
			}

		} else {
			plog.Info("reconnect ok")
			if pc.allocip == "" {
				pc.AskAllocIPAddress()
			}
			pc.conn.StartProcess()
			pc.SendHeartBeat()
			success = true
			pc.state = POLE_CLIENT_RUNING
			if pc.handler != nil {
				pc.handler(CLIENT_EVENT_RECONNECTED, pc, nil)
			}
			break
		}
	}
	if !success {
		plog.Error("reconnet failed,stop client")
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "reconnet failed").Set("type", ERROR_NETWORK))
		}
		pc.Stop()
	}
	pc.reconnecting = false
}

func (pc *PoleVpnClient) SendHeartBeat() {
	buf := make([]byte, POLE_PACKET_HEADER_LEN)
	PolePacket(buf).SetCmd(CMD_HEART_BEAT)
	PolePacket(buf).SetLen(POLE_PACKET_HEADER_LEN)
	pc.conn.Send(buf)
}

func (pc *PoleVpnClient) HeartBeat() {

	timer := time.NewTicker(time.Second * time.Duration(HEART_BEAT_INTERVAL))

	for range timer.C {
		if pc.state == POLE_CLIENT_CLOSED {
			timer.Stop()
			break
		}
		timeNow := time.Now()
		if timeNow.Sub(pc.lasttimeHeartbeat) > time.Second*HEART_BEAT_INTERVAL*WEBSOCKET_NO_HEARTBEAT_TIMES {
			plog.Error("have not recevied heartbeat for ", WEBSOCKET_NO_HEARTBEAT_TIMES, " times,close connection and reconnet")
			pc.conn.Close(true)
			pc.lasttimeHeartbeat = timeNow
			continue
		}
		pc.SendHeartBeat()
	}

}

func (pc *PoleVpnClient) Stop() {

	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state == POLE_CLIENT_CLOSED {
		plog.Error("client have been closed")
		return
	}

	if pc.conn != nil {
		pc.conn.Close(false)
	}

	if pc.tunio != nil {
		pc.tunio.Close()
	}
	pc.state = POLE_CLIENT_CLOSED

	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
	}
	pc.wg.Done()
}

package core

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/polevpn/anyvalue"
)

type PoleVpnClientVLAN struct {
	tunio             *TunIO
	conn              Conn
	state             int
	mutex             *sync.Mutex
	endpoint          string
	user              string
	pwd               string
	sni               string
	skipVerifySSL     bool
	deviceType        string
	deviceId          string
	allocip           string
	remoteip          string
	lasttimeHeartbeat time.Time
	reconnecting      bool
	wg                *sync.WaitGroup
	device            *TunDevice
	handler           func(int, PoleVpnClient, *anyvalue.AnyValue)
	host              string
}

func NewPoleVpnClientVLAN() (*PoleVpnClientVLAN, error) {

	client := &PoleVpnClientVLAN{
		conn:  nil,
		state: POLE_CLIENT_INIT,
		mutex: &sync.Mutex{},
		wg:    &sync.WaitGroup{},
	}
	return client, nil
}

func (pc *PoleVpnClientVLAN) AttachTunDevice(device *TunDevice) {
	pc.device = device
	if pc.tunio != nil {
		pc.tunio.Close()
	}

	pc.tunio = NewTunIO(TUN_DEVICE_CH_WRITE_SIZE)
	pc.tunio.SetPacketHandler(pc.handleTunPacket)
	pc.tunio.AttachDevice(device)
	pc.tunio.StartProcess()
}

func (pc *PoleVpnClientVLAN) SetEventHandler(handler func(int, PoleVpnClient, *anyvalue.AnyValue)) {
	pc.handler = handler
}

func (pc *PoleVpnClientVLAN) GetUpDownBytes() (uint64, uint64) {
	if pc.conn != nil {
		return pc.conn.GetUpDownBytes()
	}
	return 0, 0
}

func (pc *PoleVpnClientVLAN) GetRemoteIP() string {
	return pc.remoteip
}

func (pc *PoleVpnClientVLAN) SetLocalIP(ip string) {
}

func (pc *PoleVpnClientVLAN) Start(endpoint string, user string, pwd string, sni string, skipVerifySSL bool, deviceType string, deviceId string) error {

	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state != POLE_CLIENT_INIT {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "client stoped or not init").Set("type", ERROR_UNKNOWN))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return errors.New("client stoped or not init")
	}

	if sni == "" {
		sni = "www.apple.com"
	}

	pc.user = user
	pc.pwd = pwd
	pc.sni = sni
	pc.skipVerifySSL = skipVerifySSL
	pc.deviceId = deviceId
	pc.deviceType = deviceType
	var err error

	pc.host, err = GetHostByEndpoint(endpoint)
	if err != nil {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "get host fail,"+err.Error()).Set("type", ERROR_UNKNOWN))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return err
	}
	pc.remoteip, err = GetRemoteIPByEndpoint(endpoint)

	if err != nil {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "get remote ip fail,"+err.Error()).Set("type", ERROR_UNKNOWN))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return err
	}

	if strings.HasPrefix(endpoint, "wss://") {
		pc.conn = NewWebSocketConn()
	} else if strings.HasPrefix(endpoint, "h3s://") {
		endpoint = strings.Replace(endpoint, "h3s://", "https://", -1)
		pc.conn = NewHttp3Conn()
	} else {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "invalid protocol").Set("type", ERROR_UNKNOWN))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return errors.New("invalid protocol")
	}

	pc.endpoint = strings.Replace(endpoint, pc.host, pc.remoteip, -1)

	header := http.Header{}
	header.Add("Host", pc.host)

	//clear remote ip route,avoid assign address fail
	DeleteRemoteRoute(pc.remoteip + "/32")

	err = pc.conn.Connect(endpoint, user, pwd, "", sni, pc.skipVerifySSL, deviceType, deviceId, header)
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

	pc.state = POLE_CLIENT_RUNING
	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_STARTED, pc, nil)
	}

	pc.conn.SetHandler(CMD_ALLOC_IPADDR, pc.handlerAllocAdressRespose)
	pc.conn.SetHandler(CMD_S2C_IPDATA, pc.handlerIPDataResponse)
	pc.conn.SetHandler(CMD_CLIENT_CLOSED, pc.handlerConnCloseEvent)
	pc.conn.SetHandler(CMD_HEART_BEAT, pc.handlerHeartBeatRespose)
	pc.conn.StartProcess()
	pc.askAllocIPAddress()
	pc.lasttimeHeartbeat = time.Now()
	go pc.heartBeat()

	pc.wg.Add(1)
	return nil
}

func (pc *PoleVpnClientVLAN) CloseConnect(flag bool) {
	pc.conn.Close(flag)
}

func (pc *PoleVpnClientVLAN) WaitStop() {
	pc.wg.Wait()
}

func (pc *PoleVpnClientVLAN) handleTunPacket(pkt []byte) {

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

func (pc *PoleVpnClientVLAN) sendIPPacketToRemoteConn(pkt []byte) {

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

func (pc *PoleVpnClientVLAN) askAllocIPAddress() {
	buf := make([]byte, POLE_PACKET_HEADER_LEN)
	PolePacket(buf).SetCmd(CMD_ALLOC_IPADDR)
	PolePacket(buf).SetLen(POLE_PACKET_HEADER_LEN)
	pc.conn.Send(buf)
}

func (pc *PoleVpnClientVLAN) handlerAllocAdressRespose(pkt PolePacket, conn Conn) {

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

func (pc *PoleVpnClientVLAN) handlerHeartBeatRespose(pkt PolePacket, conn Conn) {
	plog.Debug("received heartbeat")
	pc.lasttimeHeartbeat = time.Now()
}

func (pc *PoleVpnClientVLAN) handlerIPDataResponse(pkt PolePacket, conn Conn) {
	if pc.tunio != nil {
		pc.tunio.Enqueue(pkt[POLE_PACKET_HEADER_LEN:])
	}
}

func (pc *PoleVpnClientVLAN) handlerConnCloseEvent(pkt PolePacket, conn Conn) {
	plog.Info("client closed,start reconnect")
	pc.reconnect()
}

func (pc *PoleVpnClientVLAN) reconnect() {

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

		header := http.Header{}
		header.Add("Host", pc.host)
		err := pc.conn.Connect(pc.endpoint, pc.user, pc.pwd, pc.allocip, pc.sni, pc.skipVerifySSL, pc.deviceType, pc.deviceId, header)

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
				time.Sleep(time.Second * RECONNECT_INTERVAL)
				plog.Error("server refuse connect")
				continue
			}

		} else {
			plog.Info("reconnect ok")
			if pc.allocip == "" {
				pc.askAllocIPAddress()
			}
			pc.conn.StartProcess()
			pc.sendHeartBeat()
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

func (pc *PoleVpnClientVLAN) sendHeartBeat() {
	buf := make([]byte, POLE_PACKET_HEADER_LEN)
	PolePacket(buf).SetCmd(CMD_HEART_BEAT)
	PolePacket(buf).SetLen(POLE_PACKET_HEADER_LEN)
	pc.conn.Send(buf)
}

func (pc *PoleVpnClientVLAN) heartBeat() {

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
		pc.sendHeartBeat()
	}

}

func (pc *PoleVpnClientVLAN) IsStoped() bool {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state == POLE_CLIENT_CLOSED || pc.state == POLE_CLIENT_INIT {
		return true
	}
	return false
}

func (pc *PoleVpnClientVLAN) Stop() {

	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state == POLE_CLIENT_CLOSED || pc.state == POLE_CLIENT_INIT {
		plog.Error("client have been closed or not start")
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

package core

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/polevpn/anyvalue"
)

type PoleVpnClientProxy struct {
	tunio         *TunIO
	state         int
	mutex         *sync.Mutex
	endpoint      string
	user          string
	pwd           string
	sni           string
	token         string
	skipVerifySSL bool
	deviceType    string
	deviceId      string
	remoteip      string
	localip       string
	wg            *sync.WaitGroup
	device        *TunDevice
	handler       func(int, PoleVpnClient, *anyvalue.AnyValue)
	host          string
	forwarder     *Forwarder
}

func NewPoleVpnClientProxy() (*PoleVpnClientProxy, error) {

	client := &PoleVpnClientProxy{
		state: POLE_CLIENT_INIT,
		mutex: &sync.Mutex{},
		wg:    &sync.WaitGroup{},
	}
	return client, nil
}

func (pc *PoleVpnClientProxy) AttachTunDevice(device *TunDevice) {
	pc.device = device
	if pc.tunio != nil {
		pc.tunio.Close()
	}

	pc.tunio = NewTunIO(TUN_DEVICE_CH_WRITE_SIZE)
	pc.tunio.SetPacketHandler(pc.handleTunPacket)
	pc.tunio.AttachDevice(device)
	pc.tunio.StartProcess()
}

func (pc *PoleVpnClientProxy) SetEventHandler(handler func(int, PoleVpnClient, *anyvalue.AnyValue)) {
	pc.handler = handler
}

func (pc *PoleVpnClientProxy) GetUpDownBytes() (uint64, uint64) {
	if pc.forwarder != nil {
		return pc.forwarder.GetUpDownBytes()
	}
	return 0, 0
}

func (pc *PoleVpnClientProxy) GetRemoteIP() string {
	return pc.remoteip
}

func (pc *PoleVpnClientProxy) SetLocalIP(ip string) {
	pc.localip = ip
}

func (pc *PoleVpnClientProxy) Start(endpoint string, user string, pwd string, sni string, skipVerifySSL bool, deviceType string, deviceId string) error {

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

	endpoint = strings.Replace(endpoint, "proxy://", "wss://", -1)

	pc.user = user
	pc.pwd = pwd
	pc.sni = sni
	pc.skipVerifySSL = skipVerifySSL
	pc.deviceId = deviceId
	pc.deviceType = deviceType
	pc.endpoint = endpoint
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

	//clear remote ip route,avoid assign address fail
	DeleteRemoteRoute(pc.remoteip + "/32")

	netDialer := net.Dialer{}

	netDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := netDialer.DialContext(ctx, network, addr)
		if err == nil {
			tcpconn := conn.(*net.TCPConn)
			tcpconn.SetNoDelay(true)
			tcpconn.SetKeepAlive(true)
			tcpconn.SetWriteBuffer(TCP_WRITE_BUFFER_SIZE)
			tcpconn.SetReadBuffer(TCP_READ_BUFFER_SIZE)
			tcpconn.SetKeepAlivePeriod(time.Second * 15)
		}
		return conn, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: pc.skipVerifySSL,
		ServerName:         pc.sni,
	}

	d := websocket.Dialer{
		NetDialContext:    netDialContext,
		TLSClientConfig:   tlsConfig,
		HandshakeTimeout:  time.Second * TCP_CONNECT_TIMEOUT,
		EnableCompression: false,
	}

	plog.Infof("start connect %s", pc.remoteip)

	_, resp, err := d.Dial(pc.endpoint, pc.newAuthHandler())

	if err != nil && err != websocket.ErrBadHandshake {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "dial error :"+err.Error()).Set("type", ERROR_NETWORK))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", ErrLoginVerify).Set("type", ERROR_NETWORK))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return ErrLoginVerify
	}

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "resp read error : "+err.Error()).Set("type", ERROR_NETWORK))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return errors.New("read auth fail," + err.Error())
	}

	av, err := anyvalue.NewFromJson(data)

	if err != nil {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", err.Error()).Set("type", ERROR_NETWORK))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return errors.New("json decode fail," + err.Error())
	}

	pc.token = av.Get("token").AsStr()

	forwarder, err := NewForwarder(pc.endpoint, pc.user, pc.token, sni)

	if err != nil {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "forwarder new err :"+err.Error()).Set("type", ERROR_NETWORK))
			pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
		}
		return errors.New("create forwarder fail," + err.Error())
	}

	forwarder.SetLocalIP(pc.localip)
	forwarder.SetMode(1)
	pc.forwarder = forwarder

	pc.forwarder.SetPacketHandler(pc.handleForwarderPacket)

	pc.state = POLE_CLIENT_RUNING
	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_STARTED, pc, nil)
	}

	pc.forwarder.StartProcess()
	pc.askAllocIPAddress()

	pc.wg.Add(1)
	return nil
}

func (pc *PoleVpnClientProxy) newAuthHandler() map[string][]string {
	h := http.Header{}

	h.Add("Pwd", pc.pwd)
	h.Add("Proto", "auth")
	h.Add("User", pc.user)
	return h
}

func (pc *PoleVpnClientProxy) CloseConnect(flag bool) {
	if pc.forwarder != nil {
		pc.forwarder.ClearConnect()
	}
}

func (pc *PoleVpnClientProxy) WaitStop() {
	pc.wg.Wait()
}

func (pc *PoleVpnClientProxy) handleTunPacket(pkt []byte) {

	if pkt == nil {
		pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("type", ERROR_IO).Set("error", "tun device close exception"))
		pc.Stop()
		return
	}

	if pc.forwarder != nil {
		pc.forwarder.Write(pkt)
	}

}

func (pc *PoleVpnClientProxy) handleForwarderPacket(pkt []byte) {
	pc.tunio.Enqueue(pkt)
}

func (pc *PoleVpnClientProxy) askAllocIPAddress() {
	av := anyvalue.New()

	av.Set("ip", "23.23.23.23")
	av.Set("dns", "1.1.1.1")
	av.Set("route", []string{})

	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_ADDRESS_ALLOCED, pc, av)
	}
}

func (pc *PoleVpnClientProxy) IsStoped() bool {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state == POLE_CLIENT_CLOSED || pc.state == POLE_CLIENT_INIT {
		return true
	}
	return false
}

func (pc *PoleVpnClientProxy) Stop() {

	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state == POLE_CLIENT_CLOSED || pc.state == POLE_CLIENT_INIT {
		plog.Error("client have been closed or not start")
		return
	}

	if pc.forwarder != nil {
		pc.forwarder.Close()
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

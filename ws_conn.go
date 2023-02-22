package core

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	CH_WEBSOCKET_WRITE_SIZE         = 100
	WEBSOCKET_HANDSHAKE_TIMEOUT     = 5
	WEBSOCKET_READ_TIMEOUT          = 30
	WEBSOCKET_TCP_WRITE_BUFFER_SIZE = 524288
	WEBSOCKET_TCP_READ_BUFFER_SIZE  = 524288
)

var ErrIPNotExist = errors.New("reconnect ip is not exist")
var ErrLoginVerify = errors.New("login verify fail")
var ErrConnectUnknown = errors.New("server unknown error")
var ErrNetwork = errors.New("network error")

type WebSocketConn struct {
	up      uint64
	down    uint64
	conn    *websocket.Conn
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	mutex   *sync.RWMutex
}

func NewWebSocketConn() *WebSocketConn {
	return &WebSocketConn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		mutex:   &sync.RWMutex{},
	}
}

func (wsc *WebSocketConn) Connect(endpoint string, user string, pwd string, ip string, sni string, skipVerifySSL bool, deviceType string, deviceId string, header http.Header) error {

	var err error

	tlsconfig := &tls.Config{
		InsecureSkipVerify: skipVerifySSL,
		ServerName:         sni,
	}

	d := websocket.Dialer{
		TLSClientConfig:   tlsconfig,
		HandshakeTimeout:  time.Second * WEBSOCKET_HANDSHAKE_TIMEOUT,
		EnableCompression: false,
	}

	conn, resp, err := d.Dial(endpoint+"?user="+url.QueryEscape(user)+"&pwd="+url.QueryEscape(pwd)+"&ip="+ip+"&deviceType="+deviceType+"&deviceId="+deviceId, header)

	if err != nil {
		if resp != nil {
			if resp.StatusCode == http.StatusBadRequest {
				return ErrIPNotExist
			} else if resp.StatusCode == http.StatusForbidden {
				return ErrLoginVerify
			} else {
				return ErrConnectUnknown
			}
		}
		plog.Error("websocket connect fail,", err)
		return ErrNetwork
	}

	wsc.mutex.Lock()
	defer wsc.mutex.Unlock()

	wsc.conn = conn
	wsc.wch = make(chan []byte, CH_WEBSOCKET_WRITE_SIZE)
	wsc.closed = false
	return nil
}

func (wsc *WebSocketConn) Close(flag bool) error {
	wsc.mutex.Lock()
	defer wsc.mutex.Unlock()

	if !wsc.closed {
		wsc.closed = true
		if wsc.wch != nil {
			close(wsc.wch)
		}
		err := wsc.conn.Close()
		if flag {
			pkt := make([]byte, POLE_PACKET_HEADER_LEN)
			PolePacket(pkt).SetCmd(CMD_CLIENT_CLOSED)
			go wsc.dispatch(pkt)
		}
		return err
	}
	return nil
}

func (wsc *WebSocketConn) String() string {
	return wsc.conn.LocalAddr().String() + "->" + wsc.conn.RemoteAddr().String()
}

func (wsc *WebSocketConn) IsClosed() bool {

	return wsc.closed
}

func (wsc *WebSocketConn) SetHandler(cmd uint16, handler func(PolePacket, Conn)) {
	wsc.handler[cmd] = handler
}

func (wsc *WebSocketConn) read() {
	defer func() {
		wsc.Close(true)
	}()

	defer PanicHandler()

	for {

		wsc.conn.SetReadDeadline(time.Now().Add(time.Second * WEBSOCKET_READ_TIMEOUT))
		mtype, pkt, err := wsc.conn.ReadMessage()
		if err != nil {
			plog.Error(wsc.String(), " conn read end,status=", err)
			return
		}
		if mtype != websocket.BinaryMessage {
			continue
		}

		atomic.AddUint64(&wsc.down, uint64(len(pkt)))
		wsc.dispatch(pkt)

	}

}

func (wsc *WebSocketConn) dispatch(pkt []byte) {
	ppkt := PolePacket(pkt)

	handler, ok := wsc.handler[ppkt.Cmd()]
	if ok {
		handler(pkt, wsc)
	} else {
		plog.Error("invalid pkt cmd=", ppkt.Cmd())
	}
}

func (wsc *WebSocketConn) drainWriteCh() {
	for {
		select {
		case _, ok := <-wsc.wch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

func (wsc *WebSocketConn) write() {
	defer PanicHandler()
	defer wsc.drainWriteCh()

	for {

		pkt, ok := <-wsc.wch
		if !ok {
			plog.Info(wsc.String(), " channel closed")
			return
		}
		if pkt == nil {
			plog.Info(wsc.String(), " exit write process")
			return
		}

		atomic.AddUint64(&wsc.up, uint64(len(pkt)))

		err := wsc.conn.WriteMessage(websocket.BinaryMessage, pkt)
		if err != nil {
			plog.Error(wsc.String(), " conn write end,status=", err)
			return
		}
	}
}

func (wsc *WebSocketConn) GetUpDownBytes() (uint64, uint64) {

	return wsc.up, wsc.down
}

func (wsc *WebSocketConn) Send(pkt []byte) {

	wsc.mutex.RLock()
	defer wsc.mutex.RUnlock()

	if wsc.IsClosed() {
		plog.Debug("websocket connection is closed,can't send pkt")
		return
	}
	if wsc.wch != nil {
		wsc.wch <- pkt
	}
}

func (wsc *WebSocketConn) StartProcess() {
	go wsc.read()
	go wsc.write()
}

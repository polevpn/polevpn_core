package core

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/polevpn/h3conn"
)

const (
	CH_HTTP3_WRITE_SIZE     = 100
	HTTP3_HANDSHAKE_TIMEOUT = 5
)

type Http3Conn struct {
	up      uint64
	down    uint64
	conn    *h3conn.Conn
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	mutex   *sync.RWMutex
}

func NewHttp3Conn() *Http3Conn {
	return &Http3Conn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		mutex:   &sync.RWMutex{},
	}
}

func (h3c *Http3Conn) Connect(endpoint string, user string, pwd string, ip string, sni string, skipVerifySSL bool, deviceType string, deviceId string, header http.Header) error {

	var err error

	tlsconfig := &tls.Config{
		InsecureSkipVerify: skipVerifySSL,
		ServerName:         sni,
	}

	client := h3conn.NewClient(tlsconfig)

	conn, resp, err := client.Connect(endpoint+"?user="+url.QueryEscape(user)+"&pwd="+url.QueryEscape(pwd)+"&ip="+ip+"&deviceType="+deviceType+"&deviceId="+deviceId, time.Second*HTTP3_HANDSHAKE_TIMEOUT, header)

	if err != nil {
		if resp != nil {
			if resp.StatusCode == http.StatusBadRequest {
				resp.Body.Close()
				return ErrIPNotExist
			} else if resp.StatusCode == http.StatusForbidden {
				resp.Body.Close()
				return ErrLoginVerify
			} else {
				resp.Body.Close()
				return ErrConnectUnknown
			}
		}
		plog.Error("http3 connect fail,", err)
		return ErrNetwork
	}

	h3c.mutex.Lock()
	defer h3c.mutex.Unlock()

	h3c.conn = conn
	h3c.wch = make(chan []byte, CH_HTTP3_WRITE_SIZE)
	h3c.closed = false
	return nil
}

func (h3c *Http3Conn) Close(flag bool) error {
	h3c.mutex.Lock()
	defer h3c.mutex.Unlock()

	if !h3c.closed {
		h3c.closed = true
		if h3c.wch != nil {
			close(h3c.wch)
		}

		err := h3c.conn.Close()
		if flag {
			pkt := make([]byte, POLE_PACKET_HEADER_LEN)
			PolePacket(pkt).SetCmd(CMD_CLIENT_CLOSED)
			go h3c.dispatch(pkt)
		}
		return err
	}
	return nil
}

func (h3c *Http3Conn) String() string {
	return h3c.conn.LocalAddr().String() + "->" + h3c.conn.RemoteAddr().String()
}

func (h3c *Http3Conn) IsClosed() bool {

	return h3c.closed
}

func (h3c *Http3Conn) SetHandler(cmd uint16, handler func(PolePacket, Conn)) {
	h3c.handler[cmd] = handler
}

func (h3c *Http3Conn) read() {
	defer func() {
		h3c.Close(true)
	}()

	defer PanicHandler()

	for {
		pkt, err := ReadPacket(h3c.conn)

		if err != nil {
			plog.Error("h3c conn read end,status=", err)
			return
		}

		atomic.AddUint64(&h3c.down, uint64(len(pkt)))
		h3c.dispatch(pkt)

	}

}

func (h3c *Http3Conn) dispatch(pkt []byte) {
	ppkt := PolePacket(pkt)

	handler, ok := h3c.handler[ppkt.Cmd()]
	if ok {
		handler(pkt, h3c)
	} else {
		plog.Error("invalid pkt cmd=", ppkt.Cmd())
	}
}

func (h3c *Http3Conn) drainWriteCh() {
	for {
		select {
		case _, ok := <-h3c.wch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

func (h3c *Http3Conn) write() {
	defer PanicHandler()
	defer h3c.drainWriteCh()

	for {
		pkt, ok := <-h3c.wch
		if !ok {
			plog.Info(h3c.String(), " channel closed")
			return
		}

		if pkt == nil {
			plog.Info(h3c.String(), " exit write process")
			return
		}
		atomic.AddUint64(&h3c.up, uint64(len(pkt)))
		_, err := h3c.conn.Write(pkt)
		if err != nil {
			plog.Error(h3c.String(), " conn write end,status=", err)
			return
		}
	}
}

func (h3c *Http3Conn) GetUpDownBytes() (uint64, uint64) {
	return h3c.up, h3c.down
}

func (h3c *Http3Conn) Send(pkt []byte) {

	h3c.mutex.RLock()
	defer h3c.mutex.RUnlock()

	if h3c.IsClosed() {
		plog.Debug("websocket connection is closed,can't send pkt")
		return
	}
	if h3c.wch != nil {
		h3c.wch <- pkt
	}
}

func (h3c *Http3Conn) StartProcess() {
	go h3c.read()
	go h3c.write()
}

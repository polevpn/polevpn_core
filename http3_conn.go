package core

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/polevpn/h3conn"
)

const (
	CH_HTTP3_WRITE_SIZE     = 100
	HTTP3_HANDSHAKE_TIMEOUT = 5
)

type Http3Conn struct {
	conn    *h3conn.Conn
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	mutex   *sync.Mutex
	localip string
}

func NewHttp3Conn() *Http3Conn {
	return &Http3Conn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		mutex:   &sync.Mutex{},
	}
}

func (h3c *Http3Conn) SetLocalIP(ip string) {
	h3c.localip = ip
}

func (h3c *Http3Conn) Connect(endpoint string, user string, pwd string, ip string, sni string, skipVerifySSL bool) error {

	var err error

	tlsconfig := &tls.Config{
		InsecureSkipVerify: skipVerifySSL,
		ServerName:         sni,
	}

	client := h3conn.NewClient(tlsconfig)

	conn, resp, err := client.Connect(endpoint+"?user="+url.QueryEscape(user)+"&pwd="+url.QueryEscape(pwd)+"&ip="+ip, time.Second*HTTP3_HANDSHAKE_TIMEOUT)

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
			h3c.wch <- nil
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
	h3c.mutex.Lock()
	defer h3c.mutex.Unlock()

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
		var preOffset = 0

		prefetch := make([]byte, 2)

		for {
			n, err := h3c.conn.Read(prefetch[preOffset:])
			if err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
					plog.Info(h3c.String(), " conn closed")
				} else {
					plog.Error(h3c.String(), " conn read exception:", err)
				}
				return
			}
			preOffset += n
			if preOffset >= 2 {
				break
			}
		}

		len := binary.BigEndian.Uint16(prefetch)

		if len < POLE_PACKET_HEADER_LEN {
			plog.Error("invalid packet len")
			continue
		}

		pkt := make([]byte, len)
		copy(pkt, prefetch)
		var offset uint16 = 2
		for {
			n, err := h3c.conn.Read(pkt[offset:])
			if err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
					plog.Info(h3c.String(), " conn closed")
				} else {
					plog.Error(h3c.String(), " conn read exception:", err)
				}
				return
			}
			offset += uint16(n)
			if offset >= len {
				break
			}
		}

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

func (h3c *Http3Conn) write() {
	defer PanicHandler()

	for {
		select {
		case pkt, ok := <-h3c.wch:
			if !ok {
				plog.Error("get pkt from write channel fail,maybe channel closed")
				return
			} else {
				if pkt == nil {
					plog.Info("exit write process")
					return
				}
				_, err := h3c.conn.Write(pkt)
				if err != nil {
					if err == io.EOF || err == io.ErrUnexpectedEOF {
						plog.Info(h3c.String(), " conn closed")
					} else {
						plog.Error(h3c.String(), " conn write exception:", err)
					}
					return
				}
			}
		}
	}
}

func (h3c *Http3Conn) Send(pkt []byte) {
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

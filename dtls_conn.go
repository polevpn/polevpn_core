package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/polevpn/anyvalue"
)

const (
	CH_DTLS_WRITE_SIZE     = 100
	DTLS_HANDSHAKE_TIMEOUT = 5
	DTLS_WRITE_BUFFER_SIZE = 524288
	DTLS_READ_BUFFER_SIZE  = 524288
)

type DTLSConn struct {
	up      uint64
	down    uint64
	conn    *dtls.Conn
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	mutex   *sync.RWMutex
}

func NewDTLSConn() *DTLSConn {
	return &DTLSConn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		mutex:   &sync.RWMutex{},
	}
}

func (dsc *DTLSConn) Connect(endpoint string, user string, pwd string, ip string, sni string, skipVerifySSL bool, header http.Header) error {

	var err error

	ctx, cancel := context.WithTimeout(context.Background(), DTLS_HANDSHAKE_TIMEOUT*time.Second)
	defer cancel()

	addr, err := net.ResolveUDPAddr("udp", endpoint)

	if err != nil {
		plog.Error("paser udp address fail,", err)
		return ErrNetwork
	}

	config := &dtls.Config{
		InsecureSkipVerify: skipVerifySSL,
		ServerName:         sni,
	}

	conn, err := dtls.DialWithContext(ctx, "udp", addr, config)

	if err != nil {
		plog.Error("dail dtls fail,", err)
		return ErrNetwork
	}

	av := anyvalue.New()
	av.Set("user", user)
	av.Set("pwd", pwd)
	av.Set("ip", ip)

	body, _ := av.EncodeJson()

	reqbuf := make([]byte, POLE_PACKET_HEADER_LEN+len(body))
	copy(reqbuf[POLE_PACKET_HEADER_LEN:], body)
	polepkt := PolePacket(reqbuf)
	polepkt.SetCmd(CMD_USER_AUTH)
	polepkt.SetLen(uint16(len(reqbuf)))

	_, err = conn.Write(polepkt)

	if err != nil {
		plog.Error("udp write auth pkt fail,", err)
		conn.Close()
		return ErrNetwork
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)

	if err != nil {
		plog.Error("udp read auth pkt fail,", err)
		conn.Close()
		return ErrNetwork
	}

	pkt := PolePacket(buf[0:n])

	resp, err := anyvalue.NewFromJson(pkt.Payload())

	if err != nil {
		conn.Close()
		plog.Error("paser auth pkt fail,", err)
		return ErrNetwork
	}

	if resp.Get("ret").AsInt() != http.StatusOK {

		conn.Close()

		if resp.Get("ret").AsInt() == http.StatusBadRequest {
			return ErrIPNotExist
		} else if resp.Get("ret").AsInt() == http.StatusForbidden {
			return ErrLoginVerify
		} else {
			return ErrConnectUnknown
		}
	}

	dsc.mutex.Lock()
	defer dsc.mutex.Unlock()

	dsc.conn = conn
	dsc.wch = make(chan []byte, CH_DTLS_WRITE_SIZE)
	dsc.closed = false
	return nil
}

func (dsc *DTLSConn) Close(flag bool) error {
	dsc.mutex.Lock()
	defer dsc.mutex.Unlock()

	if !dsc.closed {
		dsc.closed = true
		if dsc.wch != nil {
			close(dsc.wch)
		}
		err := dsc.conn.Close()
		if flag {
			pkt := make([]byte, POLE_PACKET_HEADER_LEN)
			PolePacket(pkt).SetCmd(CMD_CLIENT_CLOSED)
			go dsc.dispatch(pkt)
		}
		return err
	}
	return nil
}

func (dsc *DTLSConn) String() string {
	return dsc.conn.LocalAddr().String() + "->" + dsc.conn.RemoteAddr().String()
}

func (dsc *DTLSConn) IsClosed() bool {

	return dsc.closed
}

func (dsc *DTLSConn) SetHandler(cmd uint16, handler func(PolePacket, Conn)) {
	dsc.handler[cmd] = handler
}

func (dsc *DTLSConn) read() {
	defer func() {
		dsc.Close(true)
	}()

	defer PanicHandler()

	for {
		buf := make([]byte, 2048)
		n, err := dsc.conn.Read(buf)
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				plog.Info(dsc.String(), " conn closed")
			} else {
				plog.Error(dsc.String(), " conn read exception:", err)
			}
			return
		}

		pkt := buf[0:n]

		atomic.AddUint64(&dsc.down, uint64(len(pkt)))
		dsc.dispatch(pkt)

	}

}

func (dsc *DTLSConn) dispatch(pkt []byte) {
	ppkt := PolePacket(pkt)

	handler, ok := dsc.handler[ppkt.Cmd()]
	if ok {
		handler(pkt, dsc)
	} else {
		plog.Error("invalid pkt cmd=", ppkt.Cmd())
	}
}

func (dsc *DTLSConn) drainWriteCh() {
	for {
		select {
		case _, ok := <-dsc.wch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

func (dsc *DTLSConn) write() {
	defer PanicHandler()
	defer dsc.drainWriteCh()

	for {
		select {
		case pkt, ok := <-dsc.wch:
			if !ok {
				plog.Info("dtls conn writing channel closed")
				return
			} else {
				if pkt == nil {
					plog.Info("exit write process")
					return
				}

				atomic.AddUint64(&dsc.up, uint64(len(pkt)))

				_, err := dsc.conn.Write(pkt)
				if err != nil {
					if err == io.EOF || err == io.ErrUnexpectedEOF {
						plog.Info(dsc.String(), " conn closed")
					} else {
						plog.Error(dsc.String(), " conn write exception:", err)
					}
					return
				}
			}
		}
	}
}

func (dsc *DTLSConn) GetUpDownBytes() (uint64, uint64) {

	return dsc.up, dsc.up
}

func (dsc *DTLSConn) Send(pkt []byte) {

	dsc.mutex.RLock()
	defer dsc.mutex.RUnlock()

	if dsc.IsClosed() {
		plog.Debug("dtls connection is closed,can't send pkt")
		return
	}
	if dsc.wch != nil {
		dsc.wch <- pkt
	}
}

func (dsc *DTLSConn) StartProcess() {
	go dsc.read()
	go dsc.write()
}

package core

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/polevpn/anyvalue"
)

const (
	CH_DNS_WRITE_SIZE     = 100
	DNS_HANDSHAKE_TIMEOUT = 5
	DNS_READ_TIMEOUT      = 30
	DNS_CACHE_TIME        = 10
)

type DNSQuery struct {
	conn     *websocket.Conn
	wch      chan []byte
	closed   bool
	mutex    *sync.RWMutex
	natMutex *sync.RWMutex
	nat      map[string]*DNSSession
	timer    *time.Ticker
}

type DNSSession struct {
	rch       chan []byte
	expiredAt time.Time
}

func NewDNSQuery() *DNSQuery {
	return &DNSQuery{
		conn:     nil,
		closed:   true,
		wch:      nil,
		nat:      make(map[string]*DNSSession),
		mutex:    &sync.RWMutex{},
		natMutex: &sync.RWMutex{},
	}
}

func (dq *DNSQuery) Connect(endpoint string, user string, token string, sni string) error {

	var err error

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	}

	d := websocket.Dialer{
		TLSClientConfig:   tlsconfig,
		HandshakeTimeout:  time.Second * DNS_HANDSHAKE_TIMEOUT,
		EnableCompression: false,
	}

	header := http.Header{}

	header.Add("User", user)
	header.Add("Token", token)
	header.Add("Proto", "dns")

	conn, _, err := d.Dial(endpoint, header)

	if err != nil {
		plog.Error("dns connect fail,", err)
		return ErrNetwork
	}

	dq.mutex.Lock()
	defer dq.mutex.Unlock()

	dq.conn = conn
	dq.wch = make(chan []byte, CH_DNS_WRITE_SIZE)
	dq.closed = false

	dq.timer = time.NewTicker(time.Second)

	go func() {
		for range dq.timer.C {

			dq.natMutex.Lock()

			delKeys := make([]string, 0)

			for key, session := range dq.nat {
				if session.expiredAt.Sub(time.Now()) < 0 {
					delKeys = append(delKeys, key)
				}
			}

			for _, key := range delKeys {
				close(dq.nat[key].rch)
				delete(dq.nat, key)
			}
			dq.natMutex.Unlock()

		}
	}()

	return nil
}

func (dq *DNSQuery) Close() error {
	dq.mutex.Lock()
	defer dq.mutex.Unlock()

	if !dq.closed {
		dq.closed = true
		if dq.wch != nil {
			close(dq.wch)
		}
		if dq.timer != nil {
			dq.timer.Stop()
		}

		dq.natMutex.RLock()
		for _, session := range dq.nat {
			close(session.rch)
		}
		dq.natMutex.RUnlock()

		return dq.conn.Close()
	}
	return nil
}

func (dq *DNSQuery) String() string {
	return dq.conn.LocalAddr().String() + "->" + dq.conn.RemoteAddr().String()
}

func (dq *DNSQuery) IsClosed() bool {

	dq.mutex.RLock()
	defer dq.mutex.RUnlock()

	return dq.closed
}

func (dq *DNSQuery) read() {
	defer func() {
		dq.Close()
	}()

	defer PanicHandler()

	for {

		dq.conn.SetReadDeadline(time.Now().Add(time.Second * DNS_READ_TIMEOUT))
		mtype, pkt, err := dq.conn.ReadMessage()
		if err != nil {
			plog.Error(dq.String(), " conn read end,status=", err)
			return
		}
		if mtype != websocket.BinaryMessage {
			continue
		}
		av, err := anyvalue.NewFromJson(pkt)

		if err != nil {
			plog.Error(dq.String(), " dns message decode fail,", err)
			return
		}

		data, err := base64.StdEncoding.DecodeString(av.Get("data").AsStr())

		if err != nil {
			plog.Error(dq.String(), " dns data decode fail,", err)
			return
		}

		dq.natMutex.RLock()
		session, ok := dq.nat[av.Get("src").AsStr()+av.Get("dst").AsStr()]
		dq.natMutex.RUnlock()

		if ok {
			select {
			case session.rch <- data:
			default:
				plog.Debug("dns resp writing channel is full")
			}
			close(session.rch)
			delete(dq.nat, av.Get("src").AsStr()+av.Get("dst").AsStr())
		}
	}

}

func (dq *DNSQuery) drainWriteCh() {
	for {
		select {
		case _, ok := <-dq.wch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

func (dq *DNSQuery) write() {
	defer PanicHandler()
	defer dq.drainWriteCh()
	defer dq.Close()

	for {

		pkt, ok := <-dq.wch
		if !ok {
			plog.Info(dq.String(), " dns channel closed")
			return
		}
		if pkt == nil {
			plog.Info(dq.String(), " dns query exit write process")
			return
		}

		err := dq.conn.WriteMessage(websocket.BinaryMessage, pkt)
		if err != nil {
			plog.Error(dq.String(), " conn write end,status=", err)
			return
		}
	}
}

func (dq *DNSQuery) Query(src string, dst string, pkt []byte) (chan []byte, error) {

	dq.mutex.RLock()
	defer dq.mutex.RUnlock()

	if dq.IsClosed() {
		return nil, errors.New("dns connection is closed,can't send pkt")
	}

	av := anyvalue.New()

	av.Set("src", src)
	av.Set("dst", dst)
	av.Set("data", base64.StdEncoding.EncodeToString(pkt))

	data, err := av.EncodeJson()

	if err != nil {
		return nil, err
	}

	rch := make(chan []byte)

	dq.natMutex.Lock()
	dq.nat[src+dst] = &DNSSession{rch: rch, expiredAt: time.Now().Add(time.Second * 5)}
	dq.natMutex.Unlock()

	if dq.wch != nil {

		select {
		case dq.wch <- data:
		default:
			close(rch)
			dq.natMutex.Lock()
			delete(dq.nat, src+dst)
			dq.natMutex.Unlock()

			return nil, errors.New("dq writing channel is full")
		}
	}
	return rch, nil
}

func (dq *DNSQuery) StartProcess() {
	go dq.read()
	go dq.write()
}

package core

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/polevpn/netstack/tcpip"
	"github.com/polevpn/netstack/tcpip/adapters/gonet"
	"github.com/polevpn/netstack/tcpip/buffer"
	"github.com/polevpn/netstack/tcpip/link/channel"
	"github.com/polevpn/netstack/tcpip/network/arp"
	"github.com/polevpn/netstack/tcpip/network/ipv4"
	"github.com/polevpn/netstack/tcpip/network/ipv6"
	"github.com/polevpn/netstack/tcpip/stack"
	"github.com/polevpn/netstack/tcpip/transport/tcp"
	"github.com/polevpn/netstack/tcpip/transport/udp"
	"github.com/polevpn/netstack/waiter"
)

const (
	TCP_MAX_CONNECTION_SIZE = 1024
	FORWARD_CH_WRITE_SIZE   = 200
	MAX_BUFFER_SIZE         = 4096
	CONNECTION_IDLE_TIME    = 30
	UDP_READ_BUFFER_SIZE    = 32000
	UDP_WRITE_BUFFER_SIZE   = 32000
	TCP_READ_BUFFER_SIZE    = 32000
	TCP_WRITE_BUFFER_SIZE   = 32000
	CH_WRITE_SIZE           = 10
	TCP_CONNECT_TIMEOUT     = 5
	TCP_CONNECT_RETRY       = 3
	NETSTACK_MTU            = 1500
)

type Forwarder struct {
	s        *stack.Stack
	ep       *channel.Endpoint
	wq       *waiter.Queue
	closed   bool
	handler  func([]byte)
	localip  string
	proxy    string
	token    string
	user     string
	sni      string
	mode     int
	up       uint64
	down     uint64
	dnsquery *DNSQuery
	dnsMutex *sync.Mutex
}

func NewForwarder(proxy string, user string, token string, sni string) (*Forwarder, error) {

	forwarder := &Forwarder{}

	maddr, err := net.ParseMAC("88:88:88:88:88:88")
	if err != nil {
		return nil, err
	}

	// Create the stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol(), arp.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{tcp.NewProtocol(), udp.NewProtocol()},
	})

	ep := channel.New(FORWARD_CH_WRITE_SIZE, NETSTACK_MTU, tcpip.LinkAddress(maddr))

	if err := s.CreateNIC(1, ep); err != nil {
		return nil, errors.New(err.String())
	}

	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		return nil, errors.New(err.String())
	}

	subnet1, err := tcpip.NewSubnet(tcpip.Address(net.IPv4zero.To4()), tcpip.AddressMask(net.IPv4zero.To4()))
	if err != nil {
		return nil, err
	}

	if err := s.AddAddressRange(1, ipv4.ProtocolNumber, subnet1); err != nil {
		return nil, errors.New(err.String())
	}

	subnet2, err := tcpip.NewSubnet(tcpip.Address(net.IPv6zero.To16()), tcpip.AddressMask(net.IPv6zero.To16()))
	if err != nil {
		return nil, err
	}

	if err := s.AddAddressRange(1, ipv6.ProtocolNumber, subnet2); err != nil {
		return nil, errors.New(err.String())
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet1,
			NIC:         1,
		},
		{
			Destination: subnet2,
			NIC:         1,
		},
	})

	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		forwarder.forwardUDP(r)
	})

	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)

	tf := tcp.NewForwarder(s, 0, TCP_MAX_CONNECTION_SIZE, func(r *tcp.ForwarderRequest) {
		forwarder.forwardTCP(r)
	})

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	forwarder.closed = false
	forwarder.s = s
	forwarder.ep = ep
	forwarder.wq = &waiter.Queue{}
	forwarder.proxy = proxy
	forwarder.user = user
	forwarder.token = token
	forwarder.sni = sni
	forwarder.dnsMutex = &sync.Mutex{}
	return forwarder, nil
}

func (lf *Forwarder) SetPacketHandler(handler func([]byte)) {
	lf.handler = handler
}

func (lf *Forwarder) SetLocalIP(ip string) {
	lf.localip = ip
}

func (lf *Forwarder) SetMode(mode int) {
	lf.mode = mode
}

func (lf *Forwarder) Write(pkg []byte) {
	if lf.closed {
		return
	}
	pkgBuffer := tcpip.PacketBuffer{Data: buffer.View(pkg).ToVectorisedView()}

	version := pkg[0]
	version = version >> 4

	if version == VERSION_IP_V4 {
		lf.ep.InjectInbound(ipv4.ProtocolNumber, pkgBuffer)
	} else if version == VERSION_IP_V6 {
		lf.ep.InjectInbound(ipv6.ProtocolNumber, pkgBuffer)
	}

}

func (lf *Forwarder) read() {

	for {
		pkgInfo, err := lf.ep.Read()
		if err != nil {
			plog.Error(err)
			return
		}
		view := buffer.NewVectorisedView(1, []buffer.View{pkgInfo.Pkt.Header.View()})
		view.Append(pkgInfo.Pkt.Data)
		if lf.handler != nil {
			lf.handler(view.ToView())
		}
	}
}

func (lf *Forwarder) getDNSQuery() (*DNSQuery, error) {

	lf.dnsMutex.Lock()
	defer lf.dnsMutex.Unlock()

	if lf.dnsquery != nil && !lf.dnsquery.IsClosed() {
		return lf.dnsquery, nil
	} else {
		dnsquery := NewDNSQuery()
		err := dnsquery.Connect(lf.proxy, lf.user, lf.token, lf.sni)
		if err != nil {
			return nil, err
		}
		dnsquery.StartProcess()

		lf.dnsquery = dnsquery
		return lf.dnsquery, nil
	}
}

func (lf *Forwarder) StartProcess() {
	go lf.read()
}

func (lf *Forwarder) ClearConnect() {
}

func (lf *Forwarder) Close() {
	defer PanicHandler()

	if lf.closed {
		return
	}
	lf.closed = true
	lf.ep.Close()
	lf.s.Close()

	if lf.dnsquery != nil {
		lf.dnsquery.Close()
	}
}

func (lf *Forwarder) GetLocalTCPConn(ip string, port uint16) (net.Conn, error) {

	var err error
	localip := lf.localip
	var laddr *net.TCPAddr
	if localip != "" {
		laddr, _ = net.ResolveTCPAddr("tcp", localip+":0")
	}

	d := net.Dialer{Timeout: time.Second * TCP_CONNECT_TIMEOUT, LocalAddr: laddr}

	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}

	conn, err := d.Dial("tcp", ip+":"+strconv.Itoa(int(port)))

	if conn != nil {
		tcpconn := conn.(*net.TCPConn)
		tcpconn.SetNoDelay(true)
		tcpconn.SetKeepAlive(true)
		tcpconn.SetWriteBuffer(TCP_WRITE_BUFFER_SIZE)
		tcpconn.SetReadBuffer(TCP_READ_BUFFER_SIZE)
		tcpconn.SetKeepAlivePeriod(time.Second * 15)
	}

	return conn, err
}

func (lf *Forwarder) GetLocalUDPConn(ip string, port uint16) (net.Conn, error) {

	localip := lf.localip
	var laddr *net.UDPAddr
	if localip != "" {
		laddr, _ = net.ResolveUDPAddr("udp", localip+":0")
	}

	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}

	raddr, _ := net.ResolveUDPAddr("udp", ip+":"+strconv.Itoa(int(port)))
	conn, err := net.DialUDP("udp", laddr, raddr)

	if err != nil {
		return nil, err
	}

	conn.SetReadBuffer(UDP_READ_BUFFER_SIZE)
	conn.SetWriteBuffer(UDP_WRITE_BUFFER_SIZE)

	return conn, nil
}

func (lf *Forwarder) GetUpDownBytes() (uint64, uint64) {
	return lf.up, lf.down
}

func (lf *Forwarder) getRemoteWSConn(ip string, port uint16, proto string) (net.Conn, error) {
	var err error

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         lf.sni,
	}

	localip := lf.localip
	var laddr *net.TCPAddr
	if localip != "" {
		laddr, _ = net.ResolveTCPAddr("tcp", localip+":0")
	}

	netDialer := net.Dialer{LocalAddr: laddr}

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

	d := websocket.Dialer{
		NetDialContext:    netDialContext,
		TLSClientConfig:   tlsconfig,
		HandshakeTimeout:  time.Second * TCP_CONNECT_TIMEOUT,
		EnableCompression: false,
	}

	header := http.Header{}

	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}

	header.Add("Dst", ip)
	header.Add("Port", strconv.Itoa(int(port)))
	header.Add("User", lf.user)
	header.Add("Token", lf.token)
	header.Add("Proto", proto)

	conn, _, err := d.Dial(lf.proxy, header)

	if err != nil {
		plog.Errorf("connect to %v ws connect fail,%v", lf.proxy, err)
		return nil, err
	}

	if proto == "tcp" {
		return NewWSStreamConn(conn), nil
	} else {
		return NewWSMessageConn(conn), nil
	}
}

func (lf *Forwarder) copyStream(dst net.Conn, src net.Conn, waitTime time.Duration) (n int64) {

	buf := make([]byte, MAX_BUFFER_SIZE)

	for {
		if waitTime > 0 {
			src.SetReadDeadline(time.Now().Add(waitTime))
		}
		nr, err := src.Read(buf)

		if nr > 0 {
			if nw, err := dst.Write(buf[:nr]); err != nil {
				plog.Debugf("%v->%v,%v", dst.LocalAddr().String(), dst.RemoteAddr().String(), err.Error())
				break
			} else {
				n += int64(nw)
			}
		}

		if err != nil {
			plog.Debugf("%v->%v,%v", src.LocalAddr().String(), src.RemoteAddr().String(), err.Error())
			break
		}
	}
	return
}

func (lf *Forwarder) forwardTCP(r *tcp.ForwarderRequest) {

	defer PanicHandler()

	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		plog.Errorf("dst:%v:%v create endpoint fail,%v", r.ID().LocalAddress, r.ID().LocalPort, err)
		r.Complete(true)
		return
	}

	if lf.closed {
		r.Complete(true)
		ep.Close()
		return
	}

	idleTime := CONNECTION_IDLE_TIME

	address := r.ID().LocalAddress.String()

	if r.ID().LocalPort == 53 || r.ID().LocalPort == 853 || ((address == "208.67.222.222" || address == "208.67.222.220" || address == "8.8.8.8" || address == "8.8.4.4" || address == "1.1.1.1" || address == "1.0.0.1") && r.ID().LocalPort == 443) {
		r.Complete(true)
		ep.Close()
		return
	}

	err = ep.SetSockOptInt(tcpip.ReceiveBufferSizeOption, TCP_READ_BUFFER_SIZE)

	if err != nil {
		plog.Errorf("dst:%v:%v set endpoint fail,%v", r.ID().LocalAddress, r.ID().LocalPort, err)
		r.Complete(true)
		ep.Close()
		return
	}

	err = ep.SetSockOptInt(tcpip.SendBufferSizeOption, TCP_WRITE_BUFFER_SIZE)

	if err != nil {
		plog.Errorf("dst:%v:%v set endpoint fail,%v", r.ID().LocalAddress, r.ID().LocalPort, err)
		r.Complete(true)
		ep.Close()
		return
	}

	plog.Debugf("src:%s:%d=>dst:%s:%d tcp connect", r.ID().RemoteAddress.String(), r.ID().RemotePort, r.ID().LocalAddress.String(), r.ID().LocalPort)

	addr, _ := ep.GetLocalAddress()

	var conn net.Conn
	var remoteErr error

	conn, remoteErr = lf.getRemoteWSConn(addr.Addr.String(), addr.Port, "tcp")

	if remoteErr != nil {
		plog.Errorf("dst:%s:%d create tcp remote connect fail,%s", r.ID().LocalAddress.String(), r.ID().LocalPort, remoteErr.Error())
		r.Complete(true)
		ep.Close()
		return
	}

	defer r.Complete(false)

	lconn := gonet.NewConn(wq, ep)

	var up, down int64

	go func() {
		defer PanicHandler()
		up = lf.copyStream(conn, lconn, time.Duration(time.Second*time.Duration(idleTime)))
		conn.Close()
		lconn.Close()
	}()

	down = lf.copyStream(lconn, conn, time.Duration(time.Second*time.Duration(idleTime)))

	conn.Close()
	lconn.Close()

	lf.up += uint64(up)
	lf.down += uint64(down)
	plog.Debugf("dst:%s:%v,up:%d,down:%d tcp completed", r.ID().LocalAddress.String(), r.ID().LocalPort, up, down)

}

func (lf *Forwarder) forwardUDP(r *udp.ForwarderRequest) {

	defer PanicHandler()

	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		plog.Infof("dst:%s:%d create udp endpoint fail,%s", r.ID().LocalAddress.String(), r.ID().LocalPort, err.String())
		return
	}

	if lf.closed {
		ep.Close()
		return
	}

	idleTime := CONNECTION_IDLE_TIME

	address := r.ID().LocalAddress.String()

	if r.ID().LocalPort == 853 || ((address == "208.67.222.222" || address == "208.67.222.220" || address == "8.8.8.8" || address == "8.8.4.4" || address == "1.1.1.1" || address == "1.0.0.1") && r.ID().LocalPort == 443) {
		ep.Close()
		return
	}

	if r.ID().LocalPort == 53 {

		plog.Debugf("src:%s:%d=>dst:%s:%d udp dns query", r.ID().RemoteAddress.String(), r.ID().RemotePort, r.ID().LocalAddress.String(), r.ID().LocalPort)

		go func() {

			defer PanicHandler()

			lconn := gonet.NewUDPConn(wq, ep)
			defer lconn.Close()

			query, err := lf.getDNSQuery()

			if err != nil {
				plog.Errorf("dst:%s:%d udp dns query remote connect create fail,%s", r.ID().LocalAddress.String(), r.ID().LocalPort, err.Error())
				return
			}

			buf := make([]byte, MAX_BUFFER_SIZE)

			n, err := lconn.Read(buf)

			if err != nil {
				plog.Errorf("dst:%s:%d udp dns query read fail,%s", r.ID().LocalAddress.String(), r.ID().LocalPort, err.Error())
				return
			}

			rch, err := query.Query(r.ID().RemoteAddress.String()+":"+strconv.Itoa(int(r.ID().RemotePort)), r.ID().LocalAddress.String()+":"+strconv.Itoa(int(r.ID().LocalPort)), buf[:n])

			if err != nil {
				plog.Errorf("dst:%s:%d udp dns query fail,%s", r.ID().LocalAddress.String(), r.ID().LocalPort, err.Error())
				return
			}

			data, ok := <-rch

			if !ok {
				plog.Errorf("dst:%s:%d udp dns query fail,read channel closed", r.ID().LocalAddress.String(), r.ID().LocalPort)
				return
			}

			_, err = lconn.Write(data)

			if err != nil {
				plog.Errorf("dst:%s:%d udp dns query fail,write fail,%v", r.ID().LocalAddress.String(), r.ID().LocalPort, err)
				return
			}
			plog.Debugf("src:%s:%d=>dst:%s:%d udp dns query ok", r.ID().RemoteAddress.String(), r.ID().RemotePort, r.ID().LocalAddress.String(), r.ID().LocalPort)

		}()

		return
	}

	plog.Debugf("src:%s:%d=>dst:%s:%d udp connect", r.ID().RemoteAddress.String(), r.ID().RemotePort, r.ID().LocalAddress.String(), r.ID().LocalPort)

	go func() {

		defer PanicHandler()

		var conn net.Conn
		var remoteErr error

		conn, remoteErr = lf.getRemoteWSConn(r.ID().LocalAddress.String(), r.ID().LocalPort, "udp")

		if remoteErr != nil {
			plog.Errorf("dst:%s:%d udp remote connect create fail,%s", r.ID().LocalAddress.String(), r.ID().LocalPort, remoteErr.Error())
			ep.Close()
			return
		}

		lconn := gonet.NewUDPConn(wq, ep)

		var up, down int64

		go func() {
			defer PanicHandler()
			up = lf.copyStream(conn, lconn, time.Duration(time.Second*time.Duration(idleTime)))
			conn.Close()
			lconn.Close()
		}()

		down = lf.copyStream(lconn, conn, time.Duration(time.Second*time.Duration(idleTime)))

		conn.Close()
		lconn.Close()

		lf.up += uint64(up)
		lf.down += uint64(down)

		plog.Debugf("dst:%s:%v,up:%d,down:%d udp completed", r.ID().LocalAddress.String(), r.ID().LocalPort, up, down)

	}()

}

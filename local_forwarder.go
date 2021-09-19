package core

import (
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/polevpn/netstack/tcpip"
	"github.com/polevpn/netstack/tcpip/buffer"
	"github.com/polevpn/netstack/tcpip/link/channel"
	"github.com/polevpn/netstack/tcpip/network/arp"
	"github.com/polevpn/netstack/tcpip/network/ipv4"
	"github.com/polevpn/netstack/tcpip/stack"
	"github.com/polevpn/netstack/tcpip/transport/tcp"
	"github.com/polevpn/netstack/tcpip/transport/udp"
	"github.com/polevpn/netstack/waiter"
)

const (
	TCP_MAX_CONNECTION_SIZE  = 1024
	FORWARD_CH_WRITE_SIZE    = 4096
	UDP_MAX_BUFFER_SIZE      = 8192
	TCP_MAX_BUFFER_SIZE      = 8192
	UDP_READ_BUFFER_SIZE     = 524288
	UDP_WRITE_BUFFER_SIZE    = 262144
	TCP_READ_BUFFER_SIZE     = 524288
	TCP_WRITE_BUFFER_SIZE    = 262144
	UDP_CONNECTION_IDLE_TIME = 1
	CH_WRITE_SIZE            = 100
	TCP_CONNECT_TIMEOUT      = 5
	TCP_CONNECT_RETRY        = 3
)

type LocalForwarder struct {
	s       *stack.Stack
	ep      *channel.Endpoint
	wq      *waiter.Queue
	closed  bool
	handler func([]byte)
	localip string
}

func NewLocalForwarder() (*LocalForwarder, error) {

	forwarder := &LocalForwarder{}

	maddr, err := net.ParseMAC("01:01:01:01:01:01")
	if err != nil {
		return nil, err
	}

	// Create the stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), arp.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{tcp.NewProtocol(), udp.NewProtocol()},
	})

	ep := channel.New(FORWARD_CH_WRITE_SIZE, 1500, tcpip.LinkAddress(maddr))

	if err := s.CreateNIC(1, ep); err != nil {
		return nil, errors.New(err.String())
	}

	subnet1, err := tcpip.NewSubnet(tcpip.Address(net.IPv4(0, 0, 0, 0).To4()), tcpip.AddressMask(net.IPv4Mask(0, 0, 0, 0)))
	if err != nil {
		return nil, err
	}

	if err := s.AddAddressRange(1, ipv4.ProtocolNumber, subnet1); err != nil {
		return nil, errors.New(err.String())
	}

	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		return nil, errors.New(err.String())
	}

	subnet, err := tcpip.NewSubnet(tcpip.Address(net.IPv4(0, 0, 0, 0).To4()), tcpip.AddressMask(net.IPv4Mask(0, 0, 0, 0)))
	if err != nil {
		return nil, err
	}
	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		go forwarder.forwardUDP(r)
	})

	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)

	tf := tcp.NewForwarder(s, 0, TCP_MAX_CONNECTION_SIZE, func(r *tcp.ForwarderRequest) {
		go forwarder.forwardTCP(r)
	})

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	forwarder.closed = false
	forwarder.s = s
	forwarder.ep = ep
	forwarder.wq = &waiter.Queue{}
	return forwarder, nil

}

func (lf *LocalForwarder) SetPacketHandler(handler func([]byte)) {
	lf.handler = handler
}

func (lf *LocalForwarder) SetLocalIP(ip string) {
	lf.localip = ip
}

func (lf *LocalForwarder) Write(pkg []byte) {
	if lf.closed {
		return
	}
	pkgBuffer := tcpip.PacketBuffer{Data: buffer.NewViewFromBytes(pkg).ToVectorisedView()}
	lf.ep.InjectInbound(ipv4.ProtocolNumber, pkgBuffer)
}

func (lf *LocalForwarder) read() {
	for {
		pkgInfo, err := lf.ep.Read()
		if err != nil {
			plog.Info(err)
			return
		}
		view := buffer.NewVectorisedView(1, []buffer.View{pkgInfo.Pkt.Header.View()})
		view.Append(pkgInfo.Pkt.Data)
		if lf.handler != nil {
			lf.handler(view.ToView())
		}
	}
}

func (lf *LocalForwarder) StartProcess() {
	go lf.read()
}

func (lf *LocalForwarder) ClearConnect() {
	lf.wq.Notify(waiter.EventIn)
}

func (lf *LocalForwarder) Close() {
	defer PanicHandler()

	if lf.closed {
		return
	}
	lf.closed = true

	lf.wq.Notify(waiter.EventIn)
	time.Sleep(time.Millisecond * 100)
	lf.ep.Close()
}

func (lf *LocalForwarder) forwardTCP(r *tcp.ForwarderRequest) {

	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		plog.Error("create tcp endpint error", err)
		r.Complete(true)
		return
	}

	if lf.closed {
		r.Complete(true)
		ep.Close()
		return
	}

	plog.Debug(r.ID(), "tcp connect")

	var err1 error

	localip := lf.localip
	var laddr *net.TCPAddr
	if localip != "" {
		laddr, _ = net.ResolveTCPAddr("tcp4", localip+":0")
	}

	addr, _ := ep.GetLocalAddress()
	raddr := addr.Addr.String() + ":" + strconv.Itoa(int(addr.Port))
	var conn net.Conn
	for i := 0; i < TCP_CONNECT_RETRY; i++ {
		d := net.Dialer{Timeout: time.Second * TCP_CONNECT_TIMEOUT, LocalAddr: laddr}
		conn, err1 = d.Dial("tcp4", raddr)
		if err1 != nil {
			continue
		}
		break
	}

	if err1 != nil {
		plog.Println("conn dial fail,", err1)
		r.Complete(true)
		ep.Close()
		return
	}

	tcpconn := conn.(*net.TCPConn)
	tcpconn.SetNoDelay(true)
	tcpconn.SetKeepAlive(true)
	tcpconn.SetWriteBuffer(TCP_WRITE_BUFFER_SIZE)
	tcpconn.SetReadBuffer(TCP_READ_BUFFER_SIZE)
	tcpconn.SetKeepAlivePeriod(time.Second * 15)

	go lf.tcpRead(r, wq, ep, conn)
	go lf.tcpWrite(r, wq, ep, conn)
}

func (lf *LocalForwarder) udpRead(r *udp.ForwarderRequest, ep tcpip.Endpoint, wq *waiter.Queue, conn *net.UDPConn, timer *time.Ticker) {

	defer func() {
		plog.Debug(r.ID(), "udp closed")
		ep.Close()
		conn.Close()
	}()

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	gwaitEntry, gnotifyCh := waiter.NewChannelEntry(nil)

	lf.wq.EventRegister(&gwaitEntry, waiter.EventIn)
	defer lf.wq.EventUnregister(&gwaitEntry)

	wch := make(chan []byte, CH_WRITE_SIZE)

	defer close(wch)

	writer := func() {
		for {
			pkt, ok := <-wch
			if !ok {
				plog.Debug("udp wch closed,exit write process")
				return
			} else {
				_, err1 := conn.Write(pkt)
				if err1 != nil {
					if err1 != io.EOF && strings.Index(err1.Error(), "use of closed network connection") < 0 {
						plog.Info("udp conn write error", err1)
					}
					return
				}
			}
		}
	}

	go writer()

	lastTime := time.Now()

	for {
		var addr tcpip.FullAddress
		v, _, err := ep.Read(&addr)
		if err != nil {
			if err == tcpip.ErrWouldBlock {

				select {
				case <-notifyCh:
					continue
				case <-gnotifyCh:
					return
				case <-timer.C:
					if time.Now().Sub(lastTime) > time.Minute*UDP_CONNECTION_IDLE_TIME {
						plog.Infof("udp %v connection expired,close it", r.ID())
						timer.Stop()
						return
					} else {
						continue
					}
				}
			} else if err != tcpip.ErrClosedForReceive && err != tcpip.ErrClosedForSend {
				plog.Info("udp ep read fail,", err)
			}
			return
		}

		wch <- v
		lastTime = time.Now()
	}
}

func (lf *LocalForwarder) udpWrite(r *udp.ForwarderRequest, ep tcpip.Endpoint, wq *waiter.Queue, conn *net.UDPConn, addr *tcpip.FullAddress) {

	defer func() {
		ep.Close()
		conn.Close()
	}()

	for {
		var udppkg []byte = make([]byte, UDP_MAX_BUFFER_SIZE)
		n, err1 := conn.Read(udppkg)

		if err1 != nil {
			if err1 != io.EOF &&
				strings.Index(err1.Error(), "use of closed network connection") < 0 &&
				strings.Index(err1.Error(), "connection refused") < 0 {
				plog.Info("udp conn read error,", err1)
			}
			return
		}
		udppkg1 := udppkg[:n]
		_, _, err := ep.Write(tcpip.SlicePayload(udppkg1), tcpip.WriteOptions{To: addr})
		if err != nil {
			plog.Info("udp ep write fail,", err)
			return
		}
	}
}

func (lf *LocalForwarder) forwardUDP(r *udp.ForwarderRequest) {
	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		plog.Error("create udp endpint error", err)
		return
	}

	if lf.closed {
		ep.Close()
		return
	}

	plog.Debug(r.ID(), "udp connect")

	localip := lf.localip
	var err1 error
	var laddr *net.UDPAddr
	if localip != "" {
		laddr, _ = net.ResolveUDPAddr("udp4", localip+":0")
	}

	raddr, _ := net.ResolveUDPAddr("udp4", r.ID().LocalAddress.To4().String()+":"+strconv.Itoa(int(r.ID().LocalPort)))

	conn, err1 := net.DialUDP("udp4", laddr, raddr)
	if err1 != nil {
		plog.Error("udp conn dial error ", err1)
		ep.Close()
		return
	}

	conn.SetReadBuffer(UDP_READ_BUFFER_SIZE)
	conn.SetWriteBuffer(UDP_WRITE_BUFFER_SIZE)

	timer := time.NewTicker(time.Minute)
	addr := &tcpip.FullAddress{Addr: r.ID().RemoteAddress, Port: r.ID().RemotePort}

	go lf.udpRead(r, ep, wq, conn, timer)
	go lf.udpWrite(r, ep, wq, conn, addr)
}

func (lf *LocalForwarder) tcpRead(r *tcp.ForwarderRequest, wq *waiter.Queue, ep tcpip.Endpoint, conn net.Conn) {
	defer func() {
		plog.Debug(r.ID(), "tcp closed")
		r.Complete(true)
		ep.Close()
		conn.Close()
	}()

	// Create wait queue entry that notifies a channel.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)

	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	// Create wait queue entry that notifies a channel.
	gwaitEntry, gnotifyCh := waiter.NewChannelEntry(nil)

	lf.wq.EventRegister(&gwaitEntry, waiter.EventIn)
	defer lf.wq.EventUnregister(&gwaitEntry)

	wch := make(chan []byte, CH_WRITE_SIZE)

	defer close(wch)

	writer := func() {
		for {
			pkt, ok := <-wch
			if !ok {
				plog.Debug("wch closed,exit write process")
				return
			} else {
				_, err1 := conn.Write(pkt)
				if err1 != nil {
					if err1 != io.EOF && strings.Index(err1.Error(), "use of closed network connection") < 0 {
						plog.Infof("tcp %v conn write error,%v", r.ID(), err1)
					}
					return
				}
			}
		}
	}

	go writer()

	for {
		v, _, err := ep.Read(nil)
		if err != nil {

			if err == tcpip.ErrWouldBlock {
				select {
				case <-notifyCh:
					continue
				case <-gnotifyCh:
					return
				}

			} else if err != tcpip.ErrClosedForReceive && err != tcpip.ErrClosedForSend {
				plog.Infof("tcp %v endpoint read fail,%v", r.ID(), err)
			}
			return
		}
		wch <- v
	}
}

func (lf *LocalForwarder) tcpWrite(r *tcp.ForwarderRequest, wq *waiter.Queue, ep tcpip.Endpoint, conn net.Conn) {
	defer func() {
		ep.Close()
		conn.Close()
	}()

	for {
		var buf []byte = make([]byte, TCP_MAX_BUFFER_SIZE)
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF && strings.Index(err.Error(), "use of closed network connection") < 0 {
				plog.Infof("tcp %v conn read error,%v", r.ID(), err)
			}
			break
		}

		ep.Write(tcpip.SlicePayload(buf[:n]), tcpip.WriteOptions{})
	}
}

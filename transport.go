package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/memberlist"
	"github.com/lucas-clemente/quic-go"
)

type Config struct {
	// BindAddrs is a list of addresses to bind to.
	BindAddrs []string

	// BindPort is the port to listen on, for each address above.
	BindPort int

	// Timeout used when making connections to other nodes to send packet.
	// Zero = no timeout
	PacketDialTimeout time.Duration

	// Timeout for writing packet data. Zero = no timeout.
	PacketWriteTimeout time.Duration

	// Transport logs lot of messages at debug level, so it deserves an extra flag for turning it on
	TransportDebug bool

	// Quic TLS Configuration
	TLS *tls.Config
}

type QuicTransport struct {
	config      Config
	sessionPool *quicSessionPool
	packetCh    chan *memberlist.Packet
	connCh      chan net.Conn

	listeners  []quic.Listener
	listenerWg *sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc
}

func NewQuicTransport(config Config) (*QuicTransport, error) {
	if len(config.BindAddrs) == 0 {
		return nil, fmt.Errorf("At least one bind address is required")
	}

	var ok bool
	t := &QuicTransport{
		sessionPool: newQuicSessionPool(config.TLS),
		config:      config,
		packetCh:    make(chan *memberlist.Packet),
		connCh:      make(chan net.Conn),
		listeners:   make([]quic.Listener, len(config.BindAddrs)),
		listenerWg:  &sync.WaitGroup{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.ctx = ctx

	defer func() {
		if !ok {
			t.Shutdown()
		}
	}()

	port := config.BindPort
	for i, addr := range config.BindAddrs {

		quicConfig := &quic.Config{
			EnableDatagrams: true,
			KeepAlive:       true,
			TokenStore:      quic.NewLRUTokenStore(1000, 100),
		}

		listener, err := quic.ListenAddr(fmt.Sprintf("%s:%d", addr, port), config.TLS, quicConfig)
		if err != nil {
			return nil, err
		}

		t.listeners[i] = listener
		t.listenerWg.Add(1)
		go t.runListener(listener)
	}

	ok = true
	return t, nil
}

// PacketCh returns a channel that can be read to receive incoming
// packets from other peers. How this is set up for listening is left as
// an exercise for the concrete transport implementations.
func (t *QuicTransport) PacketCh() <-chan *memberlist.Packet {
	return t.packetCh
}

// StreamCh returns a channel that can be read to handle incoming stream
// connections from other peers. How this is set up for listening is
// left as an exercise for the concrete transport implementations.
func (t *QuicTransport) StreamCh() <-chan net.Conn {
	return t.connCh
}

// FinalAdvertiseAddr is given the user's configured values (which
// might be empty) and returns the desired IP and port to advertise to
// the rest of the cluster.
func (t *QuicTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	var advertiseAddr net.IP
	var advertisePort int
	if ip != "" {
		// If they've supplied an address, use that.
		advertiseAddr = net.ParseIP(ip)
		if advertiseAddr == nil {
			return nil, 0, fmt.Errorf("Failed to parse advertise address %q", ip)
		}

		// Ensure IPv4 conversion if necessary.
		if ip4 := advertiseAddr.To4(); ip4 != nil {
			advertiseAddr = ip4
		}
		advertisePort = port
	} else {
		if t.config.BindAddrs[0] == "0.0.0.0" {
			// Otherwise, if we're not bound to a specific IP, let's
			// use a suitable private IP address.
			var err error
			ip, err = sockaddr.GetPrivateIP()
			if err != nil {
				return nil, 0, fmt.Errorf("Failed to get interface addresses: %v", err)
			}
			if ip == "" {
				return nil, 0, fmt.Errorf("No private IP address found, and explicit IP not provided")
			}

			advertiseAddr = net.ParseIP(ip)
			if advertiseAddr == nil {
				return nil, 0, fmt.Errorf("Failed to parse advertise address: %q", ip)
			}
		} else {
			// Use the IP that we're bound to, based on the first
			// TCP listener, which we already ensure is there.
			advertiseAddr = t.listeners[0].Addr().(*net.UDPAddr).IP
		}

		// Use the port we are bound to.
		advertisePort = t.GetAutoBindPort()
	}

	return advertiseAddr, advertisePort, nil
}

// GetAutoBindPort returns the bind port that was automatically given by the
// kernel, if a bind port of 0 was given.
func (t *QuicTransport) GetAutoBindPort() int {
	// We made sure there's at least one TCP listener, and that one's
	// port was applied to all the others for the dynamic bind case.
	return t.listeners[0].Addr().(*net.UDPAddr).Port
}

// WriteTo is a packet-oriented interface that fires off the given
// payload to the given address in a connectionless fashion. This should
// return a time stamp that's as close as possible to when the packet
// was transmitted to help make accurate RTT measurements during probes.
//
// This is similar to net.PacketConn, though we didn't want to expose
// that full set of required methods to keep assumptions about the
// underlying plumbing to a minimum. We also treat the address here as a
// string, similar to Dial, so it's network neutral, so this usually is
// in the form of "host:port".
func (t *QuicTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	log.Println("writing to", addr)

	a := memberlist.Address{Addr: addr, Name: ""}
	return t.WriteToAddress(b, a)
}

func (t *QuicTransport) WriteToAddress(b []byte, addr memberlist.Address) (time.Time, error) {
	// log.Println("writing to address", addr.Name, addr.Addr)
	s, err := t.sessionPool.GetOrCreate(addr, t.config.PacketDialTimeout)
	if err != nil {
		return time.Now(), err
	}

	err = s.SendMessage(b)

	return time.Now(), err
}

// DialTimeout is used to create a connection that allows us to perform
// two-way communication with a peer. This is generally more expensive
// than packet connections so is used for more infrequent operations
// such as anti-entropy or fallback probes if the packet-oriented probe
// failed.
func (t *QuicTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	a := memberlist.Address{Addr: addr, Name: ""}
	return t.DialAddressTimeout(a, timeout)
}

func (t *QuicTransport) DialAddressTimeout(addr memberlist.Address, timeout time.Duration) (net.Conn, error) {
	log.Println("calling dialaddress", addr.Addr)
	session, err := t.sessionPool.GetOrCreate(addr, t.config.PacketDialTimeout)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	log.Println("opening stream")
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	conn := newQuicConn(session, stream)
	return conn, nil
}

// Shutdown is called when memberlist is shutting down; this gives the
// transport a chance to clean up any listeners.
func (t *QuicTransport) Shutdown() error {
	// This will avoid log spam about errors when we shut down.
	t.cancel()

	// Rip through all the connections and shut them down.
	for _, conn := range t.listeners {
		conn.Close()
	}

	// Block until all the listener threads have died.
	t.listenerWg.Wait()
	return nil
}

func (t *QuicTransport) runListener(listener quic.Listener) error {
	defer t.listenerWg.Done()

	for {
		select {
		case <-t.ctx.Done():
			return nil
		default:
		}

		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("error acception connection", err)
			continue
		}

		log.Println("accepted connection from ", session.RemoteAddr())

		t.listenerWg.Add(2)
		go t.handleStream(session)
		go t.handleDatagrams(session)
	}
}

func (t *QuicTransport) handleStream(session quic.Session) {
	defer t.listenerWg.Done()

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		stream, err := session.AcceptStream(t.ctx)
		if err != nil {
			log.Println("could not accept unitstream", err)
			return
		}

		conn := newQuicConn(session, stream)
		t.connCh <- conn
	}
}

func (t *QuicTransport) handleDatagrams(session quic.Session) {
	defer t.listenerWg.Done()
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		msg, err := session.ReceiveMessage()
		if err != nil {
			log.Println("error receiving datagram :", err)
			return
		}

		if len(msg) < 1 {
			log.Println("empty datagram")
		}

		t.packetCh <- &memberlist.Packet{
			Buf:       msg,
			From:      session.RemoteAddr(),
			Timestamp: time.Now(),
		}
	}
}

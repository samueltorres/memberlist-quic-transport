package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/memberlist"
	transport "github.com/samueltorres/memberlist-quic-transport"
)

func main() {
	log.Println("starting")

	var name string
	var bindPort int
	var bindAddress string
	var joinAddresses string
	flag.StringVar(&name, "name", "srv1", "")
	flag.IntVar(&bindPort, "bind-port", 9000, "")
	flag.StringVar(&bindAddress, "bind-address", "127.0.0.1", "")
	flag.StringVar(&joinAddresses, "join-addresses", "", "")
	flag.Parse()

	c := memberlist.DefaultLocalConfig()

	s := &state{
		mux: &sync.Mutex{},
		Members: map[string]string{
			name: name,
		},
	}

	c.Events = &eventDelegate{
		state: s,
	}
	c.Delegate = &delegate{
		state: s,
	}
	c.BindPort = bindPort
	c.BindAddr = bindAddress
	c.Name = name

	tlsCfg, err := generateTLSConfig("./certs/cert.pem", "./certs/cert-key.pem", "./certs/ca.pem")
	if err != nil {
		panic(err)
	}

	transport, err := transport.NewQuicTransport(transport.Config{
		BindAddrs: []string{bindAddress},
		BindPort:  bindPort,
		TLS:       tlsCfg,
	})

	c.Transport = transport

	if err != nil {
		panic(err)
	}

	m, err := memberlist.Create(c)
	if err != nil {
		panic(err)
	}
	if len(joinAddresses) > 0 {
		parts := strings.Split(joinAddresses, ",")
		_, err := m.Join(parts)
		if err != nil {
			panic(err)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("leaving memberlist")
	m.Leave(10 * time.Second)
}

type state struct {
	mux     *sync.Mutex
	Members map[string]string `json:"members"`
}

func (s *state) AddMember(member string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.Members[member] = member
}

func (s *state) RemoveMember(member string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.Members, member)
}

func (s *state) PrintMembers() {
	s.mux.Lock()
	defer s.mux.Unlock()
	log.Println(s.Members)
}

type delegate struct {
	state *state
}

// NodeMeta is used to retrieve meta-data about the current node
// when broadcasting an alive message. It's length is limited to
// the given byte size. This metadata is available in the Node structure.
func (d *delegate) NodeMeta(limit int) []byte {
	return []byte{}
}

// NotifyMsg is called when a user-data message is received.
// Care should be taken that this method does not block, since doing
// so would block the entire UDP packet receive loop. Additionally, the byte
// slice may be modified after the call returns, so it should be copied if needed
func (d *delegate) NotifyMsg([]byte) {
}

// GetBroadcasts is called when user data messages can be broadcast.
// It can return a list of buffers to send. Each buffer should assume an
// overhead as provided with a limit on the total byte size allowed.
// The total byte size of the resulting data to send must not exceed
// the limit. Care should be taken that this method does not block,
// since doing so would block the entire UDP packet receive loop.
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return [][]byte{}
}

// LocalState is used for a TCP Push/Pull. This is sent to
// the remote side in addition to the membership information. Any
// data can be sent here. See MergeRemoteState as well. The `join`
// boolean indicates this is for a join instead of a push/pull.
func (d *delegate) LocalState(join bool) []byte {
	b, _ := json.Marshal(d.state)
	return b
}

// MergeRemoteState is invoked after a TCP Push/Pull. This is the
// state received from the remote side and is the result of the
// remote side's LocalState call. The 'join'
// boolean indicates this is for a join instead of a push/pull.
func (d *delegate) MergeRemoteState(buf []byte, join bool) {
	log.Println("merge remote state")

	if len(buf) == 0 {
		log.Println("empty buf")
		return
	}

	log.Println("join", join)
	s := state{}
	if err := json.Unmarshal(buf, &s); err != nil {
		log.Println("error unmarshalling", err)

		return
	}

	for _, v := range s.Members {
		d.state.AddMember(v)
	}
	d.state.PrintMembers()
}

type eventDelegate struct {
	state *state
}

// NotifyJoin is invoked when a node is detected to have joined.
// The Node argument must not be modified.
func (e *eventDelegate) NotifyJoin(n *memberlist.Node) {
	log.Println("member joined", n.FullAddress())
}

// NotifyLeave is invoked when a node is detected to have left.
// The Node argument must not be modified.
func (e *eventDelegate) NotifyLeave(n *memberlist.Node) {
	e.state.RemoveMember(n.Name)
	log.Println("member leave", n.FullAddress())
	e.state.PrintMembers()
}

// NotifyUpdate is invoked when a node is detected to have
// updated, usually involving the meta data. The Node argument
// must not be modified.
func (e *eventDelegate) NotifyUpdate(n *memberlist.Node) {
	log.Println("member update", n.FullAddress())
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig(certFile string, keyFile string, caFile string) (*tls.Config, error) {

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	rootPEM, err := ioutil.ReadFile(caFile)
	if err != nil || rootPEM == nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		NextProtos:   []string{"quic-echo-example"},
	}, nil
}

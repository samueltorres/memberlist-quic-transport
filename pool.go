package transport

import (
	"crypto/tls"
	"log"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/lucas-clemente/quic-go"
)

type quicSessionPool struct {
	mux       *sync.RWMutex
	pool      map[string]quic.Session
	tlsConfig *tls.Config
}

func newQuicSessionPool(tlsConfig *tls.Config) *quicSessionPool {
	return &quicSessionPool{
		mux:       &sync.RWMutex{},
		pool:      make(map[string]quic.Session),
		tlsConfig: tlsConfig,
	}
}

func (p *quicSessionPool) GetOrCreate(addr memberlist.Address, timeout time.Duration) (quic.Session, error) {
	p.mux.Lock()
	defer p.mux.Unlock()

	key := addr.Name
	if key == "" {
		key = addr.Addr
	}

	session, ok := p.pool[key]
	if ok {
		return session, nil
	}

	quicConfig := &quic.Config{
		EnableDatagrams:      true,
		KeepAlive:            true,
		TokenStore:           quic.NewLRUTokenStore(1000, 100),
		HandshakeIdleTimeout: timeout,
	}

	log.Println("creating a new session to ", addr.Addr, addr.Name)
	session, err := quic.DialAddr(addr.Addr, p.tlsConfig, quicConfig)

	if err != nil {
		return nil, err
	}

	log.Println("session created to ", addr.Addr, addr.Name)
	p.pool[key] = session

	return session, nil
}

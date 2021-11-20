package transport

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/hashicorp/memberlist"
	"github.com/lucas-clemente/quic-go"
)

type quicSessionPool struct {
	mux       *sync.RWMutex
	pool      map[string]quic.Session
	tlsConfig *tls.Config
	logger    logr.Logger
}

func newQuicSessionPool(logger logr.Logger, tlsConfig *tls.Config) *quicSessionPool {
	return &quicSessionPool{
		mux:       &sync.RWMutex{},
		pool:      make(map[string]quic.Session),
		tlsConfig: tlsConfig,
		logger:    logger,
	}
}

func (p *quicSessionPool) Get(ctx context.Context, addr memberlist.Address, timeout time.Duration) (quic.Session, error) {
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
		HandshakeIdleTimeout: timeout,
	}

	session, err := quic.DialAddrContext(ctx, addr.Addr, p.tlsConfig, quicConfig)

	if err != nil {
		return nil, err
	}

	p.pool[key] = session

	return session, nil
}

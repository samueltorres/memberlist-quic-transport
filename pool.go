package transport

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
)

type quicSessionPool struct {
	mux  *sync.RWMutex
	pool map[string]quic.Session
}

func newQuicSessionPool() *quicSessionPool {
	return &quicSessionPool{
		mux:  &sync.RWMutex{},
		pool: make(map[string]quic.Session),
	}
}

func (p *quicSessionPool) GetOrCreate(addr string, timeout time.Duration) (quic.Session, error) {
	p.mux.Lock()
	defer p.mux.Unlock()

	session, ok := p.pool[addr]
	if ok {
		return session, nil
	}

	session, err := quic.DialAddr(addr, nil, nil)
	if err != nil {
		return nil, err
	}

	return session, nil
}

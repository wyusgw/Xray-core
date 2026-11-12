package mieru

import (
	gonet "net"
	"sync"
	"sync/atomic"
)

type IngressLimiter interface {
	Wait(n int64)
}

// Pace the raw conn, not the session: mieru buffers 4096 segments per session, so
// only blocking the client's TCP send enforces the upload limit.
var ingressConns sync.Map // remote address string -> *ingressConn

type limiterBox struct {
	limiter IngressLimiter
}

type ingressConn struct {
	gonet.Conn
	key     string
	limiter atomic.Pointer[limiterBox]
	// Once mieru reports decoded payload, pace that instead of bytes read.
	paced atomic.Bool
	conns *sync.Map
}

func (c *ingressConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.paced.Load() {
		if box := c.limiter.Load(); box != nil {
			box.limiter.Wait(int64(n))
		}
	}
	return n, err
}

func (c *ingressConn) PacePayload(n int) {
	c.paced.Store(true)
	if box := c.limiter.Load(); box != nil {
		box.limiter.Wait(int64(n))
	}
}

func (c *ingressConn) Close() error {
	ingressConns.CompareAndDelete(c.key, c)
	if c.conns != nil {
		c.conns.Delete(c)
	}
	return c.Conn.Close()
}

type ingressListener struct {
	gonet.Listener
	conns *sync.Map // *ingressConn -> struct{}
}

func (l *ingressListener) Accept() (gonet.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &ingressConn{
		Conn:  conn,
		key:   conn.RemoteAddr().String(),
		conns: l.conns,
	}
	ingressConns.Store(c.key, c)
	if l.conns != nil {
		l.conns.Store(c, struct{}{})
	}
	return c, nil
}

func AttachIngressLimiter(remote string, limiter IngressLimiter) bool {
	v, ok := ingressConns.Load(remote)
	if !ok {
		return false
	}
	v.(*ingressConn).limiter.Store(&limiterBox{limiter: limiter})
	return true
}

package mieru

import (
	gonet "net"
	"sync"
	"sync/atomic"
)

// IngressLimiter paces bytes read from a client's raw connection.
type IngressLimiter interface {
	Wait(n int64)
}

// mieru buffers up to segmentTreeCapacity (4096) segments of up to 32 KiB
// each per session before its receive window pushes back on the client, so a
// speed limit applied to the session's reader only throttles what leaves the
// server: the client still uploads at full speed into that buffer. Pacing the
// raw stream connection instead keeps the client's own TCP send blocked, so
// the upload limit is what the client actually gets.
//
// Stream connections are tracked by remote address, which is also the source
// address a mieru session reports, so the dispatcher can attach a user's
// limiter once it has identified the user.
var ingressConns sync.Map // remote address string -> *ingressConn

type limiterBox struct {
	limiter IngressLimiter
}

type ingressConn struct {
	gonet.Conn
	key     string
	limiter atomic.Pointer[limiterBox]
}

func (c *ingressConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		if box := c.limiter.Load(); box != nil {
			box.limiter.Wait(int64(n))
		}
	}
	return n, err
}

func (c *ingressConn) Close() error {
	ingressConns.CompareAndDelete(c.key, c)
	return c.Conn.Close()
}

type ingressListener struct {
	gonet.Listener
}

func (l *ingressListener) Accept() (gonet.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &ingressConn{
		Conn: conn,
		key:  conn.RemoteAddr().String(),
	}
	ingressConns.Store(c.key, c)
	return c, nil
}

// AttachIngressLimiter paces reads on the raw stream connection whose remote
// address is remote, and reports whether such a connection was found. It is a
// no-op for the packet (UDP) underlay, which has no stream to push back on.
func AttachIngressLimiter(remote string, limiter IngressLimiter) bool {
	v, ok := ingressConns.Load(remote)
	if !ok {
		return false
	}
	v.(*ingressConn).limiter.Store(&limiterBox{limiter: limiter})
	return true
}

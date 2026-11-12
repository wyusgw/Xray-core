package shadowsocks

import (
	"context"
	gonet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type countingDispatcher struct {
	routing.Dispatcher
	t *testing.T

	mu         sync.Mutex
	dispatched int
	received   int
}

func (d *countingDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	r, w := gonet.Pipe()
	d.t.Cleanup(func() { r.Close(); w.Close() })
	d.mu.Lock()
	d.dispatched++
	d.mu.Unlock()
	return &transport.Link{Reader: buf.NewReader(r), Writer: countingWriter{d}}, nil
}

func (d *countingDispatcher) counts() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dispatched, d.received
}

type countingWriter struct{ d *countingDispatcher }

func (w countingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.d.mu.Lock()
	w.d.received += len(mb)
	w.d.mu.Unlock()
	buf.ReleaseMulti(mb)
	return nil
}

func (countingWriter) Close() error { return nil }

func TestUDPSessionEndsOnRemove(t *testing.T) {
	s := &Server{validator: new(Validator), policyManager: policy.DefaultManager{}, cone: true}
	u := testUser(1)
	common.Must(s.AddUser(context.Background(), u))

	disp := &countingDispatcher{t: t}
	clientConn, serverConn := gonet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(session.ContextWithInbound(context.Background(), &session.Inbound{}))
	defer cancel()
	go func() { _ = s.Process(ctx, net.Network_UDP, serverConn, disp) }()

	send := func(step string, wantDispatched, wantReceived int) {
		t.Helper()
		if _, err := clientConn.Write(udpPacketFor(t, u)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		if d, r := disp.counts(); d != wantDispatched || r != wantReceived {
			t.Fatalf("%s: dispatched=%d received=%d, want %d and %d", step, d, r, wantDispatched, wantReceived)
		}
	}

	send("before removal", 1, 1)
	common.Must(s.RemoveUser(context.Background(), u.Email))
	send("after removal", 1, 1)
	common.Must(s.AddUser(context.Background(), u))
	send("after adding back", 2, 2)
}

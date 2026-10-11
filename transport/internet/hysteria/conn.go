package hysteria

import (
	"context"
	go_errors "errors"
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

// StreamConn is a TCP request of a client: the stream it was made on, carrying
// the bytes of the connection. The proxy answers the request with
// WriteResponse before it sends any of them.
type StreamConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr
	user   *protocol.MemoryUser

	host string
	port uint16
}

func (c *StreamConn) User() *protocol.MemoryUser {
	return c.user
}

// Target is the host and port the client asked to be connected to.
func (c *StreamConn) Target() (string, uint16) {
	return c.host, c.port
}

func (c *StreamConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *StreamConn) Write(b []byte) (int, error) { return c.stream.Write(b) }

func (c *StreamConn) Close() error {
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *StreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *StreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *StreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *StreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// UDPConn is a UDP session of a client. Its packets travel as QUIC datagrams
// of the client's connection, and the session lasts as long as the stream of
// the request that opened it.
type UDPConn struct {
	conn   *quic.Conn
	stream *quic.Stream
	user   *protocol.MemoryUser
	id     uint32

	incoming chan *UDPMessage
	df       defragger

	closeOnce sync.Once
	closed    chan struct{}
	release   func()
}

func (c *UDPConn) User() *protocol.MemoryUser {
	return c.user
}

// ReadPacket returns the next whole packet of the session and the address the
// client wants it sent to.
func (c *UDPConn) ReadPacket(ctx context.Context) (host string, port uint16, data []byte, err error) {
	for {
		select {
		case <-ctx.Done():
			return "", 0, nil, ctx.Err()
		case <-c.closed:
			return "", 0, nil, io.EOF
		case msg := <-c.incoming:
			if whole := c.df.feed(msg); whole != nil {
				return whole.Host, whole.Port, whole.Data, nil
			}
		}
	}
}

// WritePacket sends data to the client as coming from host:port.
func (c *UDPConn) WritePacket(host string, port uint16, data []byte) error {
	msg := UDPMessage{SessionID: c.id, Host: host, Port: port, FragCount: 1, Data: data}
	err := c.send(&msg)
	var tooLarge *quic.DatagramTooLargeError
	if !go_errors.As(err, &tooLarge) {
		return err
	}
	msg.MsgID = uint16(rand.Intn(0xFFFF)) + 1
	for _, frag := range fragment(msg, int(tooLarge.MaxDatagramPayloadSize)) {
		if err := c.send(&frag); err != nil {
			return err
		}
	}
	return nil
}

func (c *UDPConn) send(msg *UDPMessage) error {
	b := make([]byte, msg.size())
	msg.serialize(b)
	return c.conn.SendDatagram(b)
}

func (c *UDPConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (c *UDPConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func (c *UDPConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.release()
		c.stream.CancelRead(0)
		_ = c.stream.Close()
	})
	return nil
}

func (c *UDPConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *UDPConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *UDPConn) SetDeadline(time.Time) error      { return nil }
func (c *UDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *UDPConn) SetWriteDeadline(time.Time) error { return nil }

// udpSessions hands each datagram of a client's connection to the session it
// names.
type udpSessions struct {
	sync.RWMutex
	m    map[uint32]*UDPConn
	next uint32
}

func (s *udpSessions) open(conn *quic.Conn, stream *quic.Stream, user *protocol.MemoryUser) *UDPConn {
	s.Lock()
	defer s.Unlock()
	s.next++
	udp := &UDPConn{
		conn:     conn,
		stream:   stream,
		user:     user,
		id:       s.next,
		incoming: make(chan *UDPMessage, udpMessageChan),
		closed:   make(chan struct{}),
	}
	udp.release = func() {
		s.Lock()
		delete(s.m, udp.id)
		s.Unlock()
	}
	s.m[udp.id] = udp
	return udp
}

func (s *udpSessions) run(conn *quic.Conn) {
	for {
		datagram, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			break
		}
		msg, err := parseUDPMessage(datagram)
		if err != nil {
			continue
		}
		s.RLock()
		udp := s.m[msg.SessionID]
		s.RUnlock()
		if udp == nil {
			continue
		}
		select {
		case udp.incoming <- msg:
		default:
		}
	}
	s.RLock()
	sessions := make([]*UDPConn, 0, len(s.m))
	for _, udp := range s.m {
		sessions = append(sessions, udp)
	}
	s.RUnlock()
	for _, udp := range sessions {
		_ = udp.Close()
	}
}

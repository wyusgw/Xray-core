package hysteria_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// v1Server is a server of the first Hysteria generation, written from the
// layout of its messages rather than from this repository's client.
type v1Server struct {
	addr     string
	auth     string
	password string
	obfs     string
	recvBPS  uint64
	listener *quic.Listener

	mu       sync.Mutex
	nextID   uint32
	nextMsg  uint16
	hellos   int
	requests []string
}

// xplusConn is the reference packet obfuscation: [16 byte salt][payload xor
// sha256(key || salt)].
type xplusConn struct {
	net.PacketConn
	key []byte
}

func (c *xplusConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= 16 {
			continue
		}
		sum := sha256.Sum256(append(append([]byte{}, c.key...), buf[:16]...))
		out := n - 16
		for i := 0; i < out; i++ {
			p[i] = buf[16+i] ^ sum[i%sha256.Size]
		}
		return out, addr, nil
	}
}

func (c *xplusConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, 16+len(p))
	_, _ = rand.Read(out[:16])
	sum := sha256.Sum256(append(append([]byte{}, c.key...), out[:16]...))
	for i, b := range p {
		out[16+i] = b ^ sum[i%sha256.Size]
	}
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func newV1Server(t *testing.T, auth, obfs string) *v1Server {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil)
	key := common.Must2(x509.ParsePKCS8PrivateKey(certificate.PrivateKey))
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate.Certificate}, PrivateKey: key}},
		NextProtos:   []string{"hysteria"},
	}
	quicConf := &quic.Config{
		EnableDatagrams:      true,
		MaxDatagramFrameSize: 1200,
		MaxIdleTimeout:       20 * time.Second,
		MaxIncomingStreams:   1024,
	}
	var pktConn net.PacketConn = common.Must2(net.ListenPacket("udp", "127.0.0.1:0"))
	if obfs != "" {
		pktConn = &xplusConn{PacketConn: pktConn, key: []byte(obfs)}
	}
	tr := &quic.Transport{Conn: pktConn}
	listener := common.Must2(tr.Listen(tlsConf, quicConf))

	s := &v1Server{
		addr:     listener.Addr().String(),
		auth:     auth,
		password: auth,
		obfs:     obfs,
		recvBPS:  5_000_000,
		listener: listener,
		nextID:   100,
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = tr.Close()
		_ = pktConn.Close()
	})
	go s.serve()
	return s
}

func (s *v1Server) serve() {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *v1Server) handle(conn *quic.Conn) {
	ctx := context.Background()
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	var head [1 + 8 + 8 + 2]byte
	if _, err := io.ReadFull(control, head[:]); err != nil || head[0] != 3 {
		_ = conn.CloseWithError(1, "protocol error")
		return
	}
	auth := make([]byte, binary.BigEndian.Uint16(head[17:19]))
	if _, err := io.ReadFull(control, auth); err != nil {
		return
	}
	s.mu.Lock()
	s.hellos++
	s.mu.Unlock()
	ok := string(auth) == s.auth
	reply := []byte{0}
	if ok {
		reply[0] = 1
	}
	reply = binary.BigEndian.AppendUint64(reply, 1_000_000)
	reply = binary.BigEndian.AppendUint64(reply, s.recvBPS)
	message := "Welcome"
	if !ok {
		message = "Wrong password"
	}
	reply = binary.BigEndian.AppendUint16(reply, uint16(len(message)))
	reply = append(reply, message...)
	_, _ = control.Write(reply)
	if !ok {
		time.Sleep(200 * time.Millisecond)
		_ = conn.CloseWithError(2, "auth error")
		return
	}

	sessions := map[uint32]*net.UDPConn{}
	var sessionsMu sync.Mutex
	go func() {
		pending := map[[2]uint32][][]byte{}
		for {
			datagram, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			msg, ok := parseV1UDP(datagram)
			if !ok {
				continue
			}
			sessionsMu.Lock()
			udp := sessions[msg.session]
			sessionsMu.Unlock()
			if udp == nil {
				continue
			}
			if msg.fragCount > 1 {
				key := [2]uint32{msg.session, uint32(msg.msgID)}
				parts := pending[key]
				if parts == nil {
					parts = make([][]byte, msg.fragCount)
					pending[key] = parts
				}
				parts[msg.fragID] = append([]byte{}, msg.data...)
				whole := []byte{}
				for _, part := range parts {
					if part == nil {
						whole = nil
						break
					}
					whole = append(whole, part...)
				}
				if whole == nil {
					continue
				}
				delete(pending, key)
				msg.data = whole
			}
			target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(msg.host, fmt.Sprint(msg.port)))
			if err != nil {
				continue
			}
			_, _ = udp.WriteToUDP(msg.data, target)
		}
	}()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.request(conn, stream, sessions, &sessionsMu)
	}
}

type v1UDP struct {
	session   uint32
	host      string
	port      uint16
	msgID     uint16
	fragID    uint8
	fragCount uint8
	data      []byte
}

func parseV1UDP(b []byte) (v1UDP, bool) {
	var m v1UDP
	if len(b) < 6 {
		return m, false
	}
	m.session = binary.BigEndian.Uint32(b)
	hostLen := int(binary.BigEndian.Uint16(b[4:]))
	rest := b[6:]
	if len(rest) < hostLen+8 {
		return m, false
	}
	m.host = string(rest[:hostLen])
	rest = rest[hostLen:]
	m.port = binary.BigEndian.Uint16(rest)
	m.msgID = binary.BigEndian.Uint16(rest[2:])
	m.fragID = rest[4]
	m.fragCount = rest[5]
	dataLen := int(binary.BigEndian.Uint16(rest[6:]))
	rest = rest[8:]
	if len(rest) < dataLen {
		return m, false
	}
	m.data = rest[:dataLen]
	return m, true
}

func encodeV1UDP(m v1UDP) []byte {
	b := binary.BigEndian.AppendUint32(nil, m.session)
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.host)))
	b = append(b, m.host...)
	b = binary.BigEndian.AppendUint16(b, m.port)
	b = binary.BigEndian.AppendUint16(b, m.msgID)
	b = append(b, m.fragID, m.fragCount)
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.data)))
	return append(b, m.data...)
}

func (s *v1Server) request(conn *quic.Conn, stream *quic.Stream, sessions map[uint32]*net.UDPConn, mu *sync.Mutex) {
	var head [3]byte
	if _, err := io.ReadFull(stream, head[:]); err != nil {
		return
	}
	isUDP := head[0] != 0
	host := make([]byte, binary.BigEndian.Uint16(head[1:3]))
	if _, err := io.ReadFull(stream, host); err != nil {
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(stream, port[:]); err != nil {
		return
	}
	target := net.JoinHostPort(string(host), fmt.Sprint(binary.BigEndian.Uint16(port[:])))
	respond := func(ok bool, id uint32, message string) {
		reply := []byte{0}
		if ok {
			reply[0] = 1
		}
		reply = binary.BigEndian.AppendUint32(reply, id)
		reply = binary.BigEndian.AppendUint16(reply, uint16(len(message)))
		reply = append(reply, message...)
		_, _ = stream.Write(reply)
	}

	if !isUDP {
		s.mu.Lock()
		s.requests = append(s.requests, target)
		s.mu.Unlock()
		remote, err := net.Dial("tcp", target)
		if err != nil {
			respond(false, 0, err.Error())
			_ = stream.Close()
			return
		}
		respond(true, 0, "Connected")
		go func() { _, _ = io.Copy(remote, stream); _ = remote.Close() }()
		_, _ = io.Copy(stream, remote)
		_ = stream.Close()
		return
	}

	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.mu.Unlock()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		respond(false, 0, err.Error())
		return
	}
	mu.Lock()
	sessions[id] = udp
	mu.Unlock()
	respond(true, id, "OK")
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			const chunk = 900
			count := (n + chunk - 1) / chunk
			s.mu.Lock()
			s.nextMsg++
			msgID := s.nextMsg
			s.mu.Unlock()
			for i := 0; i < count; i++ {
				end := min((i+1)*chunk, n)
				msg := v1UDP{
					session: id, host: from.IP.String(), port: uint16(from.Port),
					msgID: msgID, fragID: uint8(i), fragCount: uint8(count), data: buf[i*chunk : end],
				}
				if err := conn.SendDatagram(encodeV1UDP(msg)); err != nil {
					return
				}
			}
		}
	}()
	_, _ = io.Copy(io.Discard, stream)
	_ = udp.Close()
}

func tcpEcho(t *testing.T) string {
	t.Helper()
	l := common.Must2(net.Listen("tcp", "127.0.0.1:0"))
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return l.Addr().String()
}

func udpEcho(t *testing.T, port string) {
	t.Helper()
	c := common.Must2(net.ListenPacket("udp", "127.0.0.1:"+port))
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteTo(buf[:n], from)
		}
	}()
}

func freePort(t *testing.T) int {
	t.Helper()
	l := common.Must2(net.Listen("tcp", "127.0.0.1:0"))
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startClient runs an instance that forwards a local port to target through
// the server over the first generation.
func startClient(t *testing.T, server *v1Server, target string, obfs string, extra string) int {
	t.Helper()
	host, port, _ := net.SplitHostPort(server.addr)
	targetHost, targetPort, _ := net.SplitHostPort(target)
	inPort := freePort(t)
	obfsSettings := ""
	if obfs != "" {
		obfsSettings = fmt.Sprintf(`"obfs":"xplus","obfsPassword":%q,`, obfs)
	}
	config := fmt.Sprintf(`{
	  "inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door",
	    "settings":{"address":%q,"port":%s,"network":"tcp,udp"}}],
	  "outbounds":[{"protocol":"hysteria","settings":{
	    "address":%q,"port":%s,"auth":%q,"up":"20mbps","down":"20mbps",%s
	    "serverName":"example.com","allowInsecure":true%s}}]
	}`, inPort, targetHost, targetPort, host, port, server.password, obfsSettings, extra)
	pb, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return inPort
}

func exchangeTCP(t *testing.T, port int, payload []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	return got
}

func exchangeUDP(t *testing.T, port int, payload []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	for i := 0; i < 5; i++ {
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		got := make([]byte, 65535)
		n, err := c.Read(got)
		if err == nil {
			return got[:n]
		}
	}
	t.Fatal("no udp echo")
	return nil
}

func TestV1TCPThroughServer(t *testing.T) {
	server := newV1Server(t, "secret", "")
	echo := tcpEcho(t)
	port := startClient(t, server, echo, "", "")

	payload := bytes.Repeat([]byte("hysteria one "), 5000)
	if got := exchangeTCP(t, port, payload); !bytes.Equal(got, payload) {
		t.Fatal("the echo differs from what was sent")
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 1 || server.requests[0] != echo {
		t.Fatalf("server saw requests %v, want [%s]", server.requests, echo)
	}
}

func TestV1ManyConnectionsShareOneSession(t *testing.T) {
	server := newV1Server(t, "secret", "")
	echo := tcpEcho(t)
	port := startClient(t, server, echo, "", "")

	for i := 0; i < 5; i++ {
		payload := []byte(fmt.Sprintf("connection %d", i))
		if got := exchangeTCP(t, port, payload); !bytes.Equal(got, payload) {
			t.Fatalf("connection %d: %q", i, got)
		}
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if server.hellos != 1 {
		t.Fatalf("%d hellos, want the one session reused", server.hellos)
	}
}

func TestV1UDPThroughServer(t *testing.T) {
	server := newV1Server(t, "secret", "")
	echo := tcpEcho(t)
	_, port, _ := net.SplitHostPort(echo)
	udpEcho(t, port)
	inPort := startClient(t, server, echo, "", "")

	small := []byte("ping")
	if got := exchangeUDP(t, inPort, small); !bytes.Equal(got, small) {
		t.Fatalf("got %q", got)
	}
	// Large enough to need fragments on the way out and back.
	large := bytes.Repeat([]byte{0xAB}, 4000)
	if got := exchangeUDP(t, inPort, large); !bytes.Equal(got, large) {
		t.Fatalf("a fragmented datagram came back as %d bytes", len(got))
	}
}

func TestV1WithObfuscation(t *testing.T) {
	server := newV1Server(t, "secret", "obfs-key")
	echo := tcpEcho(t)
	_, port, _ := net.SplitHostPort(echo)
	udpEcho(t, port)
	inPort := startClient(t, server, echo, "obfs-key", "")

	payload := []byte("through the obfuscation")
	if got := exchangeTCP(t, inPort, payload); !bytes.Equal(got, payload) {
		t.Fatalf("tcp: %q", got)
	}
	if got := exchangeUDP(t, inPort, payload); !bytes.Equal(got, payload) {
		t.Fatalf("udp: %q", got)
	}
}

func TestV1WrongPasswordIsRefused(t *testing.T) {
	server := newV1Server(t, "secret", "")
	server.password = "other"
	echo := tcpEcho(t)
	port := startClient(t, server, echo, "", "")

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("hello"))
	buf := make([]byte, 16)
	if n, err := c.Read(buf); err == nil && n > 0 {
		t.Fatalf("read %q from a refused session", buf[:n])
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.hellos == 0 || len(server.requests) != 0 {
		t.Fatalf("want a refused hello and no request, got %d hellos and %v", server.hellos, server.requests)
	}
}

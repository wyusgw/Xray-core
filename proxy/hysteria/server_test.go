package hysteria_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// startServer runs an instance with a first-generation inbound and returns its
// port.
func startServer(t *testing.T, auth, obfs string) int {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil)
	certPEM, keyPEM := certificate.ToPEM()
	lines := func(b []byte) []string {
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	obfsSettings := ""
	if obfs != "" {
		obfsSettings = fmt.Sprintf(`"obfs":"xplus","obfsPassword":%q`, obfs)
	}
	port := freePort(t)
	config := fmt.Sprintf(`{
	  "inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"hysteria",
	    "settings":{"users":[{"auth":%q,"email":"user@example.com"}]},
	    "streamSettings":{"network":"hysteria","security":"tls",
	      "tlsSettings":{"certificates":[{"certificate":%s,"key":%s}]},
	      "hysteriaSettings":{%s}}}],
	  "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]
	}`, port, auth, mustJSON(lines(certPEM)), mustJSON(lines(keyPEM)), obfsSettings)
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
	return port
}

func mustJSON(v any) string {
	return string(common.Must2(json.Marshal(v)))
}

// startClientTo runs an instance that forwards a local port to target through
// the first-generation server at 127.0.0.1:serverPort.
func startClientTo(t *testing.T, serverPort int, auth, target, obfs string) int {
	t.Helper()
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
	    "address":"127.0.0.1","port":%d,"auth":%q,"up":"20mbps","down":"20mbps",%s
	    "serverName":"example.com","allowInsecure":true}}]
	}`, inPort, targetHost, targetPort, serverPort, auth, obfsSettings)
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

func TestServerTCP(t *testing.T) {
	server := startServer(t, "secret", "")
	echo := tcpEcho(t)
	port := startClientTo(t, server, "secret", echo, "")

	payload := bytes.Repeat([]byte("hysteria one "), 5000)
	if got := exchangeTCP(t, port, payload); !bytes.Equal(got, payload) {
		t.Fatal("the echo differs from what was sent")
	}
	for i := 0; i < 3; i++ {
		small := []byte(fmt.Sprintf("connection %d", i))
		if got := exchangeTCP(t, port, small); !bytes.Equal(got, small) {
			t.Fatalf("connection %d: %q", i, got)
		}
	}
}

func TestServerUDP(t *testing.T) {
	server := startServer(t, "secret", "")
	echo := tcpEcho(t)
	_, echoPort, _ := net.SplitHostPort(echo)
	udpEcho(t, echoPort)
	port := startClientTo(t, server, "secret", echo, "")

	small := []byte("ping")
	if got := exchangeUDP(t, port, small); !bytes.Equal(got, small) {
		t.Fatalf("got %q", got)
	}
	large := bytes.Repeat([]byte{0xAB}, 4000)
	if got := exchangeUDP(t, port, large); !bytes.Equal(got, large) {
		t.Fatalf("a fragmented datagram came back as %d bytes", len(got))
	}
}

func TestServerObfuscation(t *testing.T) {
	server := startServer(t, "secret", "obfs-key")
	echo := tcpEcho(t)
	_, echoPort, _ := net.SplitHostPort(echo)
	udpEcho(t, echoPort)
	port := startClientTo(t, server, "secret", echo, "obfs-key")

	payload := []byte("through the obfuscation")
	if got := exchangeTCP(t, port, payload); !bytes.Equal(got, payload) {
		t.Fatalf("tcp: %q", got)
	}
	if got := exchangeUDP(t, port, payload); !bytes.Equal(got, payload) {
		t.Fatalf("udp: %q", got)
	}
}

func TestServerWrongAuthIsRefused(t *testing.T) {
	server := startServer(t, "secret", "")
	echo := tcpEcho(t)
	port := startClientTo(t, server, "other", echo, "")

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
}

// TestServerRawClient talks to the server with messages laid out by hand, so
// the server is checked against the reference layout and not only against this
// repository's own client.
func TestServerRawClient(t *testing.T) {
	serverPort := startServer(t, "secret", "")
	echo := tcpEcho(t)
	host, portText, _ := net.SplitHostPort(echo)
	var echoPort uint16
	_, _ = fmt.Sscan(portText, &echoPort)

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", serverPort), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hysteria"},
	}, &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := []byte{3}
	hello = binary.BigEndian.AppendUint64(hello, 1_000_000)
	hello = binary.BigEndian.AppendUint64(hello, 1_000_000)
	hello = binary.BigEndian.AppendUint16(hello, uint16(len("secret")))
	hello = append(hello, "secret"...)
	if _, err := control.Write(hello); err != nil {
		t.Fatal(err)
	}
	var reply [1 + 8 + 8 + 2]byte
	_ = control.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(control, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 1 {
		t.Fatal("the server refused a right secret")
	}
	message := make([]byte, binary.BigEndian.Uint16(reply[17:19]))
	if _, err := io.ReadFull(control, message); err != nil {
		t.Fatal(err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{0}
	request = binary.BigEndian.AppendUint16(request, uint16(len(host)))
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, echoPort)
	if _, err := stream.Write(request); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var response [1 + 4 + 2]byte
	if _, err := io.ReadFull(stream, response[:]); err != nil {
		t.Fatal(err)
	}
	if response[0] != 1 {
		t.Fatal("the server refused the request")
	}
	if _, err := io.CopyN(io.Discard, stream, int64(binary.BigEndian.Uint16(response[5:7]))); err != nil {
		t.Fatal(err)
	}
	payload := []byte("by hand")
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
}

package tuic

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

type Authenticator interface {
	Authenticate(ctx context.Context, uuid [16]byte, token []byte, tlsState tls.ConnectionState) (*protocol.MemoryUser, bool)
}

type authenticatorContextKey struct{}
type settingsContextKey struct{}
type clientContextKey struct{}
type udpContextKey struct{}

type ServerSettings struct {
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
}

func ContextWithAuthenticator(ctx context.Context, authenticator Authenticator) context.Context {
	return context.WithValue(ctx, authenticatorContextKey{}, authenticator)
}

func AuthenticatorFromContext(ctx context.Context) Authenticator {
	authenticator, _ := ctx.Value(authenticatorContextKey{}).(Authenticator)
	return authenticator
}

func ContextWithServerSettings(ctx context.Context, settings ServerSettings) context.Context {
	return context.WithValue(ctx, settingsContextKey{}, settings)
}

func ServerSettingsFromContext(ctx context.Context) ServerSettings {
	settings, _ := ctx.Value(settingsContextKey{}).(ServerSettings)
	return settings
}

// ContextWithClient carries the outbound's TUIC client into the transport
// dialer, which is where the QUIC connection actually gets established.
func ContextWithClient(ctx context.Context, client *Client) context.Context {
	return context.WithValue(ctx, clientContextKey{}, client)
}

func ClientFromContext(ctx context.Context) *Client {
	client, _ := ctx.Value(clientContextKey{}).(*Client)
	return client
}

// ContextWithUDP marks the request as a UDP relay so the dialer hands back a
// TUIC packet session instead of a relay stream.
func ContextWithUDP(ctx context.Context, udp bool) context.Context {
	return context.WithValue(ctx, udpContextKey{}, udp)
}

func UDPFromContext(ctx context.Context) bool {
	udp, _ := ctx.Value(udpContextKey{}).(bool)
	return udp
}

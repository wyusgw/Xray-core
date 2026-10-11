// Package hysteria is the server transport of the first Hysteria generation,
// named `hysteria` in a config; the second generation is `hysteria2`. The
// outbound lives in proxy/hysteria and dials by itself, so only the listening
// side needs a transport.
package hysteria

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy/hysteria2/account"
	"github.com/xtls/xray-core/transport/internet"
)

//go:generate protoc -I ../../.. --go_out=../../.. --go_opt=paths=source_relative transport/internet/hysteria/config.proto

const protocolName = "hysteria"

const (
	defaultALPN       = "hysteria"
	protocolVersion   = 3
	controlTimeout    = 10 * time.Second
	maxDatagramFrame  = 1200
	udpMessageChan    = 1024
	authFailDelay     = 200 * time.Millisecond
	closeCodeProtocol = 1
	closeCodeAuth     = 2

	// The flow control windows of the reference implementation.
	streamWindow = 15728640
	connWindow   = 67108864
)

type validatorKey struct{}

func ContextWithValidator(ctx context.Context, v *account.Validator) context.Context {
	return context.WithValue(ctx, validatorKey{}, v)
}

func ValidatorFromContext(ctx context.Context) *account.Validator {
	v, _ := ctx.Value(validatorKey{}).(*account.Validator)
	return v
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

// Package hysteria is the outbound of the first Hysteria generation, named
// `hysteria` in a config; the second generation is `hysteria2`.
//
// The two generations share a name and little else: the handshake, the request
// messages, the UDP framing and the packet obfuscation all differ. As in other
// clients, the first generation is therefore its own outbound with its own wire
// code, apart from the second generation's.
package hysteria

import (
	"github.com/xtls/xray-core/common/errors"
)

// Regenerates config.pb.go after config.proto changes. Run it with
// `go generate ./proxy/hysteria/` from the repository root; it needs protoc
// and a protoc-gen-go on PATH. Only this proto is regenerated on purpose:
// `infra/vprotogen` walks every .proto in the tree.
//go:generate protoc -I ../.. --go_out=../.. --go_opt=paths=source_relative proxy/hysteria/config.proto

const protocolName = "hysteria"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}

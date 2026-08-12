package mieru

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

const protocolName = "mieru"

// Config carries no settings of its own. Everything the listener needs comes
// from the inbound's own config, handed over through the context in context.go,
// because mieru's parameters (users, underlay, MTU) are protocol settings rather
// than stream settings. The type exists so `"network": "mieru"` resolves to a
// registered transport like every other one.
type Config struct{}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

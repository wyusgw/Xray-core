package conf

import (
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/mieru"
	"google.golang.org/protobuf/proto"
)

type MieruClientConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	// Inclusive "start-end" range, for servers listening on many ports.
	// Mutually exclusive with Port.
	PortRange    string `json:"portRange"`
	Transport    string `json:"transport"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Multiplexing string `json:"multiplexing"`
	// "HANDSHAKE_STANDARD" (1-RTT) or "HANDSHAKE_NO_WAIT" (0-RTT).
	HandshakeMode string `json:"handshakeMode"`
	MTU           int32  `json:"mtu"`
	Level         uint32 `json:"level"`
	Email         string `json:"email"`
}

func (c *MieruClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("mieru: server address is required")
	}
	if c.Username == "" {
		return nil, errors.New("mieru: username is required")
	}
	if c.Password == "" {
		return nil, errors.New("mieru: password is required")
	}

	// mieru speaks its own obfuscated transport rather than riding on Xray's,
	// so this picks how the client reaches the server. It is unrelated to the
	// network of the traffic being proxied.
	transport := strings.ToUpper(strings.TrimSpace(c.Transport))
	switch transport {
	case "":
		transport = "TCP"
	case "TCP", "UDP":
	default:
		return nil, errors.New(`mieru: "transport" must be either "TCP" or "UDP", got: `, c.Transport)
	}

	// Normalised like transport, so a profile spelling it in lower case is
	// accepted rather than rejected for a difference that carries no meaning.
	multiplexing := strings.ToUpper(strings.TrimSpace(c.Multiplexing))
	if multiplexing != "" {
		switch multiplexing {
		case "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH":
		default:
			return nil, errors.New("mieru: unsupported multiplexing level: ", c.Multiplexing)
		}
	}

	handshakeMode := strings.ToUpper(strings.TrimSpace(c.HandshakeMode))
	if handshakeMode != "" {
		switch handshakeMode {
		case "HANDSHAKE_DEFAULT", "HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT":
		default:
			return nil, errors.New("mieru: unsupported handshake mode: ", c.HandshakeMode)
		}
	}

	if c.MTU < 0 {
		return nil, errors.New("mieru: mtu must not be negative")
	}

	cfg := &mieru.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Level: c.Level,
				Email: c.Email,
				Account: serial.ToTypedMessage(&mieru.Account{
					Username: c.Username,
					Password: c.Password,
				}),
			},
		},
		Transport:     transport,
		Multiplexing:  multiplexing,
		HandshakeMode: handshakeMode,
		Mtu:           c.MTU,
	}

	if c.PortRange != "" {
		if c.Port != 0 {
			return nil, errors.New(`mieru: set either "port" or "portRange", not both`)
		}
		start, end, err := parseMieruPortRange(c.PortRange)
		if err != nil {
			return nil, err
		}
		cfg.PortRangeStart = start
		cfg.PortRangeEnd = end
	} else if c.Port == 0 {
		return nil, errors.New(`mieru: "port" or "portRange" is required`)
	}

	return cfg, nil
}

// parseMieruPortRange reads an inclusive "start-end" port range.
func parseMieruPortRange(value string) (uint32, uint32, error) {
	start, end, found := strings.Cut(strings.TrimSpace(value), "-")
	if !found {
		return 0, 0, errors.New(`mieru: "portRange" must look like "2090-2099", got: `, value)
	}
	first, err := parseMieruPort(start)
	if err != nil {
		return 0, 0, err
	}
	last, err := parseMieruPort(end)
	if err != nil {
		return 0, 0, err
	}
	if first > last {
		return 0, 0, errors.New(`mieru: "portRange" start is greater than its end: `, value)
	}
	return first, last, nil
}

func parseMieruPort(value string) (uint32, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || port == 0 || port > 65535 {
		return 0, errors.New(`mieru: invalid port in "portRange": `, value)
	}
	return uint32(port), nil
}

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
	transport, err := normalizeMieruTransport(c.Transport)
	if err != nil {
		return nil, err
	}

	multiplexing, err := normalizeMieruMultiplexing(c.Multiplexing)
	if err != nil {
		return nil, err
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

// MieruServerConfig is Inbound configuration.
//
// mieru binds its own sockets, so the listening port comes from the inbound
// itself and the only thing settable here is how it listens. Users are usually
// added at runtime through the handler service rather than listed up front,
// which is why "clients" may be empty.
type MieruServerConfig struct {
	Users   []*MieruUserConfig `json:"users"`
	Clients []*MieruUserConfig `json:"clients"`
	// "TCP" or "UDP" — the underlay to accept on, not the network of the
	// proxied traffic. Defaults to TCP when empty.
	Transport string `json:"transport"`
	// Applies to the UDP underlay only. Zero means mieru's default.
	Mtu int32 `json:"mtu"`
	// Accepted for symmetry with the outbound. Multiplexing is chosen by the
	// client and negotiated in-band, so this is validated and otherwise unused.
	Multiplexing string `json:"multiplexing"`
}

// MieruUserConfig is user configuration.
type MieruUserConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

// Build implements Buildable.
func (c *MieruServerConfig) Build() (proto.Message, error) {
	if c.Clients != nil {
		c.Users = c.Clients
	}

	transport, err := normalizeMieruTransport(c.Transport)
	if err != nil {
		return nil, err
	}
	multiplexing, err := normalizeMieruMultiplexing(c.Multiplexing)
	if err != nil {
		return nil, err
	}
	if c.Mtu < 0 {
		return nil, errors.New("mieru: mtu must not be negative")
	}

	config := &mieru.ServerConfig{
		Users:        make([]*protocol.User, len(c.Users)),
		Transport:    transport,
		Mtu:          c.Mtu,
		Multiplexing: multiplexing,
	}
	for idx, rawUser := range c.Users {
		if rawUser.Username == "" {
			return nil, errors.New("mieru: username is required")
		}
		if rawUser.Password == "" {
			return nil, errors.New("mieru: password is required")
		}
		config.Users[idx] = &protocol.User{
			Level: uint32(rawUser.Level),
			Email: rawUser.Email,
			Account: serial.ToTypedMessage(&mieru.Account{
				Username: rawUser.Username,
				Password: rawUser.Password,
			}),
		}
	}

	return config, nil
}

// normalizeMieruTransport upper-cases the underlay name so a config spelling it
// in lower case is accepted rather than rejected for a difference that carries
// no meaning.
func normalizeMieruTransport(value string) (string, error) {
	switch transport := strings.ToUpper(strings.TrimSpace(value)); transport {
	case "":
		return "TCP", nil
	case "TCP", "UDP":
		return transport, nil
	default:
		return "", errors.New(`mieru: "transport" must be either "TCP" or "UDP", got: `, value)
	}
}

func normalizeMieruMultiplexing(value string) (string, error) {
	multiplexing := strings.ToUpper(strings.TrimSpace(value))
	switch multiplexing {
	case "", "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH":
		return multiplexing, nil
	default:
		return "", errors.New("mieru: unsupported multiplexing level: ", value)
	}
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

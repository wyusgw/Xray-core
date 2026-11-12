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
	Address       *Address `json:"address"`
	Port          uint16   `json:"port"`
	PortRange     string   `json:"portRange"`
	Transport     string   `json:"transport"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Multiplexing  string   `json:"multiplexing"`
	HandshakeMode string   `json:"handshakeMode"`
	MTU           int32    `json:"mtu"`
	Level         uint32   `json:"level"`
	Email         string   `json:"email"`
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

type MieruServerConfig struct {
	Users     []*MieruUserConfig `json:"users"`
	Clients   []*MieruUserConfig `json:"clients"`
	Transport string             `json:"transport"`
	Mtu       int32              `json:"mtu"`
	// Validated only: the client negotiates multiplexing in-band.
	Multiplexing string `json:"multiplexing"`
}

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

package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/mieru"
)

func buildMieruConfig(t *testing.T, raw string) (*mieru.ClientConfig, error) {
	t.Helper()
	config := new(MieruClientConfig)
	if err := json.Unmarshal([]byte(raw), config); err != nil {
		t.Fatalf("failed to parse mieru settings: %v", err)
	}
	message, err := config.Build()
	if err != nil {
		return nil, err
	}
	built, ok := message.(*mieru.ClientConfig)
	if !ok {
		t.Fatalf("unexpected message type %T", message)
	}
	return built, nil
}

func TestMieruClientConfig(t *testing.T) {
	built, err := buildMieruConfig(t, `{
		"address": "mieru.example.com",
		"port": 2999,
		"transport": "tcp",
		"username": "user",
		"password": "secret",
		"multiplexing": "MULTIPLEXING_LOW",
		"handshakeMode": "HANDSHAKE_STANDARD",
		"mtu": 1400
	}`)
	if err != nil {
		t.Fatal(err)
	}

	if built.GetServer().GetPort() != 2999 {
		t.Errorf("unexpected port: %d", built.GetServer().GetPort())
	}
	// Normalised to upper case so the handler can switch on it without
	// re-folding the case of whatever the profile happened to spell.
	if built.GetTransport() != "TCP" {
		t.Errorf("unexpected transport: %q", built.GetTransport())
	}
	if built.GetMultiplexing() != "MULTIPLEXING_LOW" {
		t.Errorf("unexpected multiplexing: %q", built.GetMultiplexing())
	}
	if built.GetHandshakeMode() != "HANDSHAKE_STANDARD" {
		t.Errorf("unexpected handshake mode: %q", built.GetHandshakeMode())
	}
	if built.GetMtu() != 1400 {
		t.Errorf("unexpected mtu: %d", built.GetMtu())
	}
	if built.GetServer().GetUser() == nil {
		t.Fatal("server user is missing")
	}
}

func TestMieruClientConfigDefaultsToTCP(t *testing.T) {
	built, err := buildMieruConfig(t, `{
		"address": "mieru.example.com",
		"port": 2999,
		"username": "user",
		"password": "secret"
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if built.GetTransport() != "TCP" {
		t.Errorf("unexpected transport: %q", built.GetTransport())
	}
}

func TestMieruClientConfigPortRange(t *testing.T) {
	built, err := buildMieruConfig(t, `{
		"address": "mieru.example.com",
		"portRange": "2090-2099",
		"username": "user",
		"password": "secret"
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if built.GetPortRangeStart() != 2090 || built.GetPortRangeEnd() != 2099 {
		t.Errorf(
			"unexpected port range: %d-%d",
			built.GetPortRangeStart(),
			built.GetPortRangeEnd(),
		)
	}
	if built.GetServer().GetPort() != 0 {
		t.Errorf("expected no single port: %d", built.GetServer().GetPort())
	}
}

func TestMieruClientConfigRejectsInvalidSettings(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  string
	}{
		{"no address", `{"port":2999,"username":"u","password":"p"}`},
		{"no username", `{"address":"a.example.com","port":2999,"password":"p"}`},
		{"no password", `{"address":"a.example.com","port":2999,"username":"u"}`},
		{"no port at all", `{"address":"a.example.com","username":"u","password":"p"}`},
		// Ambiguous rather than harmless: the two disagree about which port to use.
		{"port and range together", `{"address":"a.example.com","port":2999,"portRange":"2090-2099","username":"u","password":"p"}`},
		{"unsupported transport", `{"address":"a.example.com","port":2999,"transport":"quic","username":"u","password":"p"}`},
		{"unsupported multiplexing", `{"address":"a.example.com","port":2999,"multiplexing":"MULTIPLEXING_MAX","username":"u","password":"p"}`},
		{"unsupported handshake mode", `{"address":"a.example.com","port":2999,"handshakeMode":"HANDSHAKE_FAST","username":"u","password":"p"}`},
		{"reversed range", `{"address":"a.example.com","portRange":"2099-2090","username":"u","password":"p"}`},
		{"range without a dash", `{"address":"a.example.com","portRange":"2090","username":"u","password":"p"}`},
		{"zero port in range", `{"address":"a.example.com","portRange":"0-2099","username":"u","password":"p"}`},
		{"negative mtu", `{"address":"a.example.com","port":2999,"mtu":-1,"username":"u","password":"p"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := buildMieruConfig(t, testCase.raw); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

package shadowsocks

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func newTestUsers(n int, cipher CipherType) []*protocol.MemoryUser {
	users := make([]*protocol.MemoryUser, n)
	for i := range users {
		account, err := (&Account{Password: fmt.Sprintf("password-%d", i), CipherType: cipher}).AsAccount()
		common.Must(err)
		users[i] = &protocol.MemoryUser{Email: fmt.Sprintf("user-%d", i), Account: account}
	}
	return users
}

func newTestValidator(users []*protocol.MemoryUser) *Validator {
	v := new(Validator)
	for _, u := range users {
		common.Must(v.Add(u))
	}
	return v
}

// tcpHandshake returns the first 50 bytes a client sends for user, which
// is what the server reads before looking the user up.
func tcpHandshake(t testing.TB, user *protocol.MemoryUser) []byte {
	var out bytes.Buffer
	w, err := WriteTCPRequest(&protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("example.com"),
		Port:    443,
		User:    user,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	common.Must(w.WriteMultiBuffer(buf.MergeBytes(nil, []byte("GET / HTTP/1.1\r\n\r\n"))))
	if out.Len() < 50 {
		t.Fatalf("handshake is %d bytes", out.Len())
	}
	return out.Bytes()[:50]
}

func lookup(v *Validator, bs []byte, key string) *protocol.MemoryUser {
	u, _, _, _, err := v.GetWithCache(bs, protocol.RequestCommandTCP, key)
	if err != nil {
		return nil
	}
	return u
}

func TestValidatorFindsUsersThroughEveryCacheLevel(t *testing.T) {
	for _, cipher := range []CipherType{CipherType_AES_128_GCM, CipherType_AES_256_GCM, CipherType_CHACHA20_POLY1305} {
		users := newTestUsers(200, cipher)
		v := newTestValidator(users)
		for round := range 3 { // full scan, then first-level, then again
			for i, u := range users {
				key := fmt.Sprintf("10.0.%d.%d", i/250, i%250)
				if round == 2 {
					key = "192.0.2.1" // a new IP: second level, then full scan
				}
				if got := lookup(v, tcpHandshake(t, u), key); got != u {
					t.Fatalf("%v round %d user %d: got %v", cipher, round, i, got)
				}
			}
		}
		if got := lookup(v, tcpHandshake(t, newTestUsers(201, cipher)[200]), "10.0.0.1"); got != nil {
			t.Fatalf("%v: unknown user matched %s", cipher, got.Email)
		}
	}
}

func TestValidatorDelRemovesEveryCachedCopy(t *testing.T) {
	users := newTestUsers(50, CipherType_AES_128_GCM)
	v := newTestValidator(users)
	victim := users[7]
	hs := tcpHandshake(t, victim)

	// Cache the victim under many IPs, so that some share a first-level shard.
	for i := range 200 {
		if lookup(v, hs, fmt.Sprintf("198.51.100.%d", i)) != victim {
			t.Fatal("victim not found before Del")
		}
	}
	common.Must(v.Del(victim.Email))
	for i := range 200 {
		if u := lookup(v, hs, fmt.Sprintf("198.51.100.%d", i)); u != nil {
			t.Fatalf("deleted user still matched from 198.51.100.%d", i)
		}
	}
	if u := lookup(v, hs, "203.0.113.9"); u != nil {
		t.Fatal("deleted user still matched from a new IP")
	}
}

func TestValidatorDelDuringLookups(t *testing.T) {
	users := newTestUsers(20, CipherType_AES_128_GCM)
	v := newTestValidator(users)
	handshakes := make([][]byte, len(users))
	for i, u := range users {
		handshakes[i] = tcpHandshake(t, u)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !stop.Load(); n++ {
				i := (n + g) % len(users)
				lookup(v, handshakes[i], fmt.Sprintf("192.0.2.%d", n%4))
			}
		}()
	}
	for _, u := range users[:10] {
		common.Must(v.Del(u.Email))
	}
	stop.Store(true)
	wg.Wait()

	for i, u := range users {
		got := lookup(v, handshakes[i], "192.0.2.1")
		if i < 10 && got != nil {
			t.Fatalf("deleted user %s still matched", u.Email)
		}
		if i >= 10 && got != u {
			t.Fatalf("user %s not matched", u.Email)
		}
	}
}

func TestValidatorUDPAmongManyUsers(t *testing.T) {
	users := newTestUsers(100, CipherType_CHACHA20_POLY1305)
	v := newTestValidator(users)
	payload := bytes.Repeat([]byte("udp payload "), 100)
	for _, i := range []int{0, 57, 99, 57} {
		packet, err := EncodeUDPPacket(&protocol.RequestHeader{
			Version: Version,
			Command: protocol.RequestCommandUDP,
			Address: net.LocalHostIP,
			Port:    53,
			User:    users[i],
		}, payload)
		common.Must(err)
		req, data, err := DecodeUDPPacketWithCache(v, packet, "192.0.2.7")
		if err != nil {
			t.Fatalf("user %d: %v", i, err)
		}
		if req.User != users[i] || !bytes.Equal(data.Bytes(), payload) {
			t.Fatalf("user %d: decoded wrong user or payload", i)
		}
	}
}

func BenchmarkValidatorFullScan(b *testing.B) {
	users := newTestUsers(1000, CipherType_AES_128_GCM)
	v := newTestValidator(users)
	hs := tcpHandshake(b, users[len(users)-1])
	b.ReportAllocs()
	for b.Loop() {
		if lookup(v, hs, "") == nil {
			b.Fatal("not found")
		}
	}
}

func TestValidatorBehindRelay(t *testing.T) {
	users := newTestUsers(30, CipherType_AES_128_GCM)
	v := newTestValidator(users)
	handshakes := make([][]byte, len(users))
	for i, u := range users {
		handshakes[i] = tcpHandshake(t, u)
	}

	// Every user arrives from the relay's address, concurrently.
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range 60 {
				i := (n*7 + g) % len(users)
				if got := lookup(v, handshakes[i], "203.0.113.1"); got != users[i] {
					t.Errorf("user %d: got %v", i, got)
				}
			}
		}()
	}
	wg.Wait()
	if s := v.GetStats(); !s.IsRelayNode || s.DefenseEnabled {
		t.Fatalf("relay=%v defense=%v, want relay detected and defense off", s.IsRelayNode, s.DefenseEnabled)
	}
	for i, u := range users {
		if got := lookup(v, handshakes[i], "203.0.113.1"); got != u {
			t.Fatalf("user %d not matched behind relay", i)
		}
	}
}

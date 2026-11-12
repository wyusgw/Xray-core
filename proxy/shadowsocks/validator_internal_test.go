package shadowsocks

import (
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func testUser(i int) *protocol.MemoryUser {
	account, err := (&Account{
		Password:   fmt.Sprintf("password-%d", i),
		CipherType: CipherType_AES_128_GCM,
	}).AsAccount()
	common.Must(err)
	return &protocol.MemoryUser{Email: fmt.Sprintf("user%d@example.com", i), Account: account}
}

func udpPacketFor(t *testing.T, user *protocol.MemoryUser) []byte {
	t.Helper()
	data, err := EncodeUDPPacket(&protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandUDP,
		Address: net.LocalHostIP,
		Port:    53,
		User:    user,
	}, []byte("payload"))
	common.Must(err)
	return append([]byte(nil), data.Bytes()...)
}

func TestScanLimiter(t *testing.T) {
	l := newScanLimiter()
	const ip = "203.0.113.1"
	for i := 0; i < scanBurst; i++ {
		if !l.Allow(ip) {
			t.Fatalf("blocked after %d failures, want %d allowed", i, scanBurst)
		}
		l.Fail(ip)
	}
	if l.Allow(ip) {
		t.Fatal("still allowed after burst exhausted")
	}
	if !l.Allow("203.0.113.2") {
		t.Fatal("other IP blocked")
	}

	s := l.shard(ip)
	s.buckets[ip].last -= int64(scanRefill)
	if !l.Allow(ip) {
		t.Fatal("not allowed after refill interval")
	}

	l.Success(ip)
	if _, ok := s.buckets[ip]; ok {
		t.Fatal("success did not clear record")
	}
}

func TestScanLimiterBounded(t *testing.T) {
	l := newScanLimiter()
	for i := 0; i < scanShards*scanShardCap*2; i++ {
		l.Fail(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	for i := range l.shards {
		if n := len(l.shards[i].buckets); n > scanShardCap {
			t.Fatalf("shard %d holds %d entries, cap %d", i, n, scanShardCap)
		}
	}
}

func TestValidatorFullScanLimited(t *testing.T) {
	v := new(Validator)
	for i := 0; i < scanLimitMinUsers; i++ {
		common.Must(v.Add(testUser(i)))
	}
	expired := udpPacketFor(t, testUser(-1)) // not a user, like an expired one
	const badIP = "198.51.100.7"
	for i := 0; i < scanBurst; i++ {
		if _, _, _, _, err := v.GetWithCache(expired, protocol.RequestCommandUDP, badIP); err != ErrNotFound {
			t.Fatalf("attempt %d: err = %v", i, err)
		}
	}
	if v.scanLimit.Allow(badIP) {
		t.Fatal("expired client not limited")
	}

	good := testUser(42)
	u, _, _, _, err := v.GetWithCache(udpPacketFor(t, good), protocol.RequestCommandUDP, "198.51.100.8")
	if err != nil || u.Email != good.Email {
		t.Fatalf("good user from clean IP: user=%v err=%v", u, err)
	}

	time.Sleep(recentRebuildInterval + 50*time.Millisecond)
	u, _, _, _, err = v.GetWithCache(udpPacketFor(t, good), protocol.RequestCommandUDP, badIP)
	if err != nil || u.Email != good.Email {
		t.Fatalf("recent user from limited IP: user=%v err=%v", u, err)
	}
}

func TestValidatorFewUsersNotLimited(t *testing.T) {
	v := new(Validator)
	common.Must(v.Add(testUser(1)))
	expired := udpPacketFor(t, testUser(-1))
	for i := 0; i < scanBurst*2; i++ {
		v.GetWithCache(expired, protocol.RequestCommandUDP, "192.0.2.1")
	}
	if !v.scanLimit.Allow("192.0.2.1") {
		t.Fatal("small validator should not limit full scans")
	}
}

func TestValidatorDelKeepsIndex(t *testing.T) {
	v := new(Validator)
	const n = 50
	users := make([]*protocol.MemoryUser, n)
	for i := range users {
		users[i] = testUser(i)
		common.Must(v.Add(users[i]))
	}
	for i := 0; i < n; i += 3 {
		common.Must(v.Del(users[i].Email))
	}
	common.Must(v.UpdateUser(users[1].Email, testUser(1)))

	if len(v.users) != len(v.userPos) {
		t.Fatalf("users=%d userPos=%d", len(v.users), len(v.userPos))
	}
	for i, u := range v.users {
		if v.userPos[u] != i {
			t.Fatalf("userPos[%s]=%d, want %d", u.Email, v.userPos[u], i)
		}
		if v.GetByEmail(u.Email) != u {
			t.Fatalf("emailIndex mismatch for %s", u.Email)
		}
	}
	for i := 0; i < n; i += 3 {
		if v.GetByEmail(users[i].Email) != nil {
			t.Fatalf("%s still present", users[i].Email)
		}
	}
	if err := v.Del(users[0].Email); err == nil {
		t.Fatal("deleting twice succeeded")
	}
}

func BenchmarkExpiredClientFullScan(b *testing.B) {
	v := new(Validator)
	for i := 0; i < 10000; i++ {
		common.Must(v.Add(testUser(i)))
	}
	data, err := EncodeUDPPacket(&protocol.RequestHeader{
		Version: Version, Command: protocol.RequestCommandUDP,
		Address: net.LocalHostIP, Port: 53, User: testUser(-1),
	}, []byte("payload"))
	common.Must(err)
	pkt := append([]byte(nil), data.Bytes()...)
	b.Run("limited", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v.GetWithCache(pkt, protocol.RequestCommandUDP, "198.51.100.9")
		}
	})
	b.Run("unlimited", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v.GetWithCache(pkt, protocol.RequestCommandUDP, "")
		}
	})
}

func fillRecent(v *Validator, users []*protocol.MemoryUser) {
	now := time.Now().UnixNano()
	for i, u := range users {
		v.userCache.PutWithSuccess(fmt.Sprintf("10.1.%d.%d", i>>8, i&255), u)
		e, _ := v.userCache.recent.users.Load(u.Email)
		e.(*successUserEntry).lastAccess.Store(now - int64(i)*int64(time.Millisecond))
	}
	v.userCache.recent.builtAt.Store(0) // force a snapshot rebuild
}

func TestValidatorThrottledIPTriesFewRecentUsers(t *testing.T) {
	v := new(Validator)
	for i := 0; i < scanLimitMinUsers*2; i++ {
		common.Must(v.Add(testUser(i)))
	}
	fillRecent(v, v.users[:scanLimitedRecentUsers*2])
	near := v.users[scanLimitedRecentUsers-1] // 64th most recent
	far := v.users[scanLimitedRecentUsers]    // 65th

	const badIP = "198.51.100.20"
	expired := udpPacketFor(t, testUser(-1))
	for i := 0; i < scanBurst; i++ {
		v.GetWithCache(expired, protocol.RequestCommandUDP, badIP)
	}
	if !v.scanThrottled(badIP) {
		t.Fatal("IP not throttled")
	}

	if u, _, _, _, err := v.GetWithCache(udpPacketFor(t, near), protocol.RequestCommandUDP, badIP); err != nil || u != near {
		t.Fatalf("recent user within limit: user=%v err=%v", u, err)
	}
	if _, _, _, _, err := v.GetWithCache(udpPacketFor(t, far), protocol.RequestCommandUDP, badIP); err != ErrNotFound {
		t.Fatalf("recent user beyond limit from throttled IP: err=%v", err)
	}
	if u, _, _, _, err := v.GetWithCache(udpPacketFor(t, far), protocol.RequestCommandUDP, "198.51.100.21"); err != nil || u != far {
		t.Fatalf("recent user beyond limit from clean IP: user=%v err=%v", u, err)
	}
}

func BenchmarkThrottledIPManyRecentUsers(b *testing.B) {
	v := new(Validator)
	for i := 0; i < 10000; i++ {
		common.Must(v.Add(testUser(i)))
	}
	fillRecent(v, v.users)
	pkt := udpPacketFor(&testing.T{}, testUser(-1))
	for i := 0; i < scanBurst; i++ {
		v.GetWithCache(pkt, protocol.RequestCommandUDP, "198.51.100.9")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.GetWithCache(pkt, protocol.RequestCommandUDP, "198.51.100.9")
	}
}

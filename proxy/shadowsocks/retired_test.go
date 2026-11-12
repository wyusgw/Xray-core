package shadowsocks

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
)

func newTestValidator(t testing.TB, n int) *Validator {
	v := new(Validator)
	for i := 0; i < n; i++ {
		common.Must(v.Add(testUser(i)))
	}
	return v
}

func udpGet(v *Validator, pkt []byte, ip string) (*protocol.MemoryUser, error) {
	u, _, _, _, err := v.GetWithCache(pkt, protocol.RequestCommandUDP, ip)
	return u, err
}

func TestRelayWithExpiredClients(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers*2)
	const relay = "192.0.2.10"

	var expired [][]byte
	for i := 0; i < 10; i++ {
		u := v.users[len(v.users)-1]
		expired = append(expired, udpPacketFor(t, u))
		common.Must(v.Del(u.Email))
	}
	for round := 0; round < scanBurst*3; round++ {
		for _, pkt := range expired {
			if _, err := udpGet(v, pkt, relay); err != ErrNotFound {
				t.Fatalf("expired client: err = %v", err)
			}
		}
	}
	if !v.scanLimit.Allow(relay) {
		t.Fatal("relay IP limited by expired clients")
	}
	if n := len(v.scanLimit.Retired(relay)); n != len(expired) {
		t.Fatalf("relay remembers %d removed users, want %d", n, len(expired))
	}

	good := v.users[7]
	if u, err := udpGet(v, udpPacketFor(t, good), relay); err != nil || u != good {
		t.Fatalf("new client behind relay: user=%v err=%v", u, err)
	}
	if len(v.scanLimit.Retired(relay)) != len(expired) {
		t.Fatal("success forgot the removed users of the relay")
	}
}

func TestRetiredUserAddedBack(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers)
	u := v.users[3]
	pkt := udpPacketFor(t, u)
	const ip = "192.0.2.20"

	common.Must(v.Del(u.Email))
	for i := 0; i < 3; i++ {
		if _, err := udpGet(v, pkt, ip); err != ErrNotFound {
			t.Fatalf("removed user: err = %v", err)
		}
	}
	back := testUser(3) // same key, new object
	common.Must(v.Add(back))
	if got, err := udpGet(v, pkt, ip); err != nil || got != back {
		t.Fatalf("user added back: user=%v err=%v", got, err)
	}
	if len(v.scanLimit.Retired(ip)) != 0 {
		t.Fatal("user added back is still remembered as removed")
	}
}

func TestRetiredOldKeyAfterUpdate(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers)
	old := v.users[5]
	oldPkt := udpPacketFor(t, old)

	account, err := (&Account{Password: "new-password", CipherType: CipherType_AES_128_GCM}).AsAccount()
	common.Must(err)
	updated := &protocol.MemoryUser{Email: old.Email, Account: account}
	common.Must(v.UpdateUser(old.Email, updated))

	const ip = "192.0.2.30"
	for i := 0; i < scanBurst*2; i++ {
		if _, err := udpGet(v, oldPkt, ip); err != ErrNotFound {
			t.Fatalf("old key: err = %v", err)
		}
	}
	if !v.scanLimit.Allow(ip) {
		t.Fatal("old key counted as failures")
	}
	if got, err := udpGet(v, udpPacketFor(t, updated), ip); err != nil || got != updated {
		t.Fatalf("new key: user=%v err=%v", got, err)
	}
}

func TestJunkStillLimited(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers+1)
	common.Must(v.Del(v.users[0].Email)) // have a removed user
	junk := udpPacketFor(t, testUser(-1))
	const ip = "192.0.2.40"
	for i := 0; i < scanBurst; i++ {
		udpGet(v, junk, ip)
	}
	if v.scanLimit.Allow(ip) {
		t.Fatal("junk not limited")
	}
}

func TestFullScanGate(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers)
	good := v.users[11]
	pkt := udpPacketFor(t, good)

	for i := 0; i < cap(fullScanSlots); i++ {
		fullScanSlots <- struct{}{}
	}
	start := time.Now()
	_, err := udpGet(v, pkt, "192.0.2.50")
	waited := time.Since(start)
	for i := 0; i < cap(fullScanSlots); i++ {
		<-fullScanSlots
	}
	if err != ErrNotFound || waited < fullScanWait {
		t.Fatalf("with no free slot: err=%v waited=%v", err, waited)
	}
	if !v.scanLimit.Allow("192.0.2.50") || v.scanLimit.Retired("192.0.2.50") != nil {
		t.Fatal("a request without a slot was recorded")
	}
	if u, err := udpGet(v, pkt, "192.0.2.50"); err != nil || u != good {
		t.Fatalf("with a free slot: user=%v err=%v", u, err)
	}
}

func TestRetiredUsersBounded(t *testing.T) {
	var r retiredUsers
	now := time.Now()
	for i := 0; i < maxRetiredUsers+100; i++ {
		r.add(testUser(i), now)
	}
	if len(r.byKey) != maxRetiredUsers {
		t.Fatalf("kept %d removed users, want %d", len(r.byKey), maxRetiredUsers)
	}
	if r.contains(testUser(0)) || !r.contains(r.list[len(r.list)-1].user) {
		t.Fatal("did not drop the oldest")
	}

	r = retiredUsers{}
	r.add(testUser(1), now.Add(-retiredUserTTL-time.Minute))
	r.add(testUser(2), now)
	if len(r.byKey) != 1 || len(r.list) != 1 {
		t.Fatalf("expired user kept: byKey=%d list=%d", len(r.byKey), len(r.list))
	}
}

func TestRetiredPerIPBounded(t *testing.T) {
	l := newScanLimiter()
	for i := 0; i < maxRetiredPerIP+10; i++ {
		l.AddRetired("192.0.2.60", testUser(i))
	}
	got := l.Retired("192.0.2.60")
	if len(got) != maxRetiredPerIP || got[len(got)-1].Email != testUser(maxRetiredPerIP+9).Email {
		t.Fatalf("kept %d, last %v", len(got), got[len(got)-1].Email)
	}
}

func BenchmarkExpiredClientsBehindRelay(b *testing.B) {
	v := newTestValidator(b, 10000)
	const relay = "192.0.2.70"
	var pkts [][]byte
	for i := 0; i < maxRetiredPerIP; i++ {
		u := v.users[len(v.users)-1]
		pkts = append(pkts, udpPacketFor(&testing.T{}, u))
		common.Must(v.Del(u.Email))
		udpGet(v, pkts[i], relay)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := udpGet(v, pkts[i%len(pkts)], relay); err != ErrNotFound {
			b.Fatal(err)
		}
	}
}

func TestRetiredConcurrent(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers*2)
	users := append([]*protocol.MemoryUser(nil), v.users[:16]...)
	pkts := make([][]byte, len(users))
	for i, u := range users {
		pkts[i] = udpPacketFor(t, u)
	}
	done := make(chan struct{})
	for g := 0; g < 4; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				udpGet(v, pkts[(g+i)%len(pkts)], "192.0.2.80")
			}
		}(g)
	}
	for i := 0; i < 50; i++ {
		u := users[i%len(users)]
		if v.Del(u.Email) == nil {
			common.Must(v.Add(u))
		}
	}
	for g := 0; g < 4; g++ {
		<-done
	}
}

func TestRetireRemovedBeforeStart(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers+1)
	gone := testUser(-5) // removed while the process was not running
	active := v.users[2]
	v.Retire([]*protocol.MemoryUser{gone, active})

	const relay = "192.0.2.90"
	pkt := udpPacketFor(t, gone)
	for i := 0; i < scanBurst*2; i++ {
		if _, err := udpGet(v, pkt, relay); err != ErrNotFound {
			t.Fatalf("removed user: err = %v", err)
		}
	}
	if !v.scanLimit.Allow(relay) {
		t.Fatal("clients of a retired user limited the IP")
	}
	if u, err := udpGet(v, udpPacketFor(t, active), relay); err != nil || u != active {
		t.Fatalf("active user passed to Retire: user=%v err=%v", u, err)
	}
}

func TestSharedKeyNotRetired(t *testing.T) {
	v := newTestValidator(t, scanLimitMinUsers)
	account, err := (&Account{Password: "shared", CipherType: CipherType_AES_128_GCM}).AsAccount()
	common.Must(err)
	a := &protocol.MemoryUser{Email: "a@example.com", Account: account}
	b := &protocol.MemoryUser{Email: "b@example.com", Account: account}
	common.Must(v.Add(a))
	common.Must(v.Add(b))
	common.Must(v.Del(a.Email))
	v.Retire([]*protocol.MemoryUser{a})

	pkt := udpPacketFor(t, b)
	const ip = "192.0.2.91"
	for i := 0; i < 3; i++ {
		if u, err := udpGet(v, pkt, ip); err != nil || u != b {
			t.Fatalf("user sharing a removed user's key: user=%v err=%v", u, err)
		}
	}
	common.Must(v.Del(b.Email))
	if !v.retired.contains(b) {
		t.Fatal("last user of the key not retired")
	}
}

func TestFewUsersManyRetiredLimited(t *testing.T) {
	v := newTestValidator(t, 8)
	retired := make([]*protocol.MemoryUser, scanLimitMinUsers)
	for i := range retired {
		retired[i] = testUser(1000 + i)
	}
	v.Retire(retired)
	junk := udpPacketFor(t, testUser(-1))
	const ip = "192.0.2.60"
	for i := 0; i < scanBurst; i++ {
		udpGet(v, junk, ip)
	}
	if v.scanLimit.Allow(ip) {
		t.Fatal("junk not limited with many removed users")
	}
	if u, err := udpGet(v, udpPacketFor(t, v.users[3]), "192.0.2.61"); err != nil || u != v.users[3] {
		t.Fatalf("user from another IP: user=%v err=%v", u, err)
	}
}

func TestDelMixedCaseEmailLeavesCache(t *testing.T) {
	v := newTestValidator(t, 2)
	u := testUser(100)
	u.Email = "Mixed@Example.com"
	common.Must(v.Add(u))
	const ip = "192.0.2.70"
	if got, err := udpGet(v, udpPacketFor(t, u), ip); err != nil || got != u {
		t.Fatalf("user=%v err=%v", got, err)
	}
	common.Must(v.Del("mixed@example.com"))
	if users := v.userCache.GetMultiUser(ip); len(users) != 0 {
		t.Fatalf("IP cache still holds %v", users)
	}
	if _, ok := v.userCache.recent.users.Load(u.Email); ok {
		t.Fatal("recent users still hold the removed user")
	}
}

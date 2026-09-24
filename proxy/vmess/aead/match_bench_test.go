package aead

import (
	"fmt"
	"testing"
	"time"
)

func benchHolder(n int) (*AuthIDDecoderHolder, [][16]byte) {
	h := NewAuthIDDecoderHolder()
	keys := make([][16]byte, n)
	for i := range keys {
		copy(keys[i][:], KDF16([]byte(fmt.Sprintf("user-%d", i)), "bench"))
		h.AddUser(keys[i], i)
	}
	return h, keys
}

// BenchmarkMatch10k measures one handshake's user lookup among 10k users,
// for a user found after trying about half of them on average.
func BenchmarkMatch10k(b *testing.B) {
	h, keys := benchHolder(10000)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		b.StopTimer()
		// Spread over the whole list: the old map-based holder tried users
		// in random order, so users early in the list would flatter a
		// slice-based one.
		authID := CreateAuthID(keys[(i*7919)%len(keys)][:], time.Now().Unix())
		b.StartTimer()
		if _, err := h.Match(authID); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMatch10kUnknown measures a lookup that fails, which tries every
// user: an expired user's client, or a probe.
func BenchmarkMatch10kUnknown(b *testing.B) {
	h, _ := benchHolder(10000)
	authID := CreateAuthID(KDF16([]byte("nobody"), "bench"), time.Now().Unix())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.Match(authID); err != ErrNotFound {
			b.Fatal(err)
		}
	}
}

// BenchmarkMatch10kFromKnownSource measures a client reconnecting from the
// address it last authenticated from.
func BenchmarkMatch10kFromKnownSource(b *testing.B) {
	h, keys := benchHolder(10000)
	i := 0
	for b.Loop() {
		i++
		u := (i * 7919) % len(keys)
		source := fmt.Sprintf("10.%d.%d.1", u>>8, u&0xff)
		b.StopTimer()
		authID := CreateAuthID(keys[u][:], time.Now().Unix())
		warm := CreateAuthID(keys[u][:], time.Now().Unix())
		if _, err := h.MatchFrom(warm, source); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if _, err := h.MatchFrom(authID, source); err != nil {
			b.Fatal(err)
		}
	}
}

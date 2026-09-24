package aead

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

func TestMatchAfterRemovals(t *testing.T) {
	h, keys := benchHolder(300)
	r := rand.New(rand.NewPCG(1, 2))
	removed := map[int]bool{}
	for len(removed) < 100 {
		i := r.IntN(len(keys))
		if !removed[i] {
			removed[i] = true
			h.RemoveUser(keys[i])
		}
	}
	for i, k := range keys {
		for _, source := range []string{"", "192.0.2.1"} {
			got, err := h.MatchFrom(CreateAuthID(k[:], time.Now().Unix()), source)
			if removed[i] {
				if err != ErrNotFound {
					t.Fatalf("removed user %d from %q: got %v, %v", i, source, got, err)
				}
			} else if err != nil || got != i {
				t.Fatalf("user %d from %q: got %v, %v", i, source, got, err)
			}
		}
	}
}

func TestMatchFromSkipsRemovedHintedUser(t *testing.T) {
	h, keys := benchHolder(50)
	const source = "198.51.100.7"
	if got, err := h.MatchFrom(CreateAuthID(keys[3][:], time.Now().Unix()), source); err != nil || got != 3 {
		t.Fatalf("got %v, %v", got, err)
	}
	h.RemoveUser(keys[3])
	if _, err := h.MatchFrom(CreateAuthID(keys[3][:], time.Now().Unix()), source); err != ErrNotFound {
		t.Fatalf("removed user still matched from its hinted source: %v", err)
	}
	h.AddUser(keys[3], "re-added")
	if got, err := h.MatchFrom(CreateAuthID(keys[3][:], time.Now().Unix()), source); err != nil || got != "re-added" {
		t.Fatalf("re-added user: got %v, %v", got, err)
	}
}

func TestMatchReportsSkewedClock(t *testing.T) {
	h, keys := benchHolder(20)
	for _, source := range []string{"", "203.0.113.5", "203.0.113.5"} {
		authID := CreateAuthID(keys[5][:], time.Now().Unix()-1000)
		if _, err := h.MatchFrom(authID, source); err != ErrInvalidTime {
			t.Fatalf("from %q: got %v, want ErrInvalidTime", source, err)
		}
	}
}

func TestMatchRejectsReplay(t *testing.T) {
	h, keys := benchHolder(20)
	authID := CreateAuthID(keys[9][:], time.Now().Unix())
	if _, err := h.MatchFrom(authID, "192.0.2.9"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.MatchFrom(authID, "192.0.2.9"); err != ErrReplay {
		t.Fatalf("got %v, want ErrReplay", err)
	}
}

func TestMatchFromConcurrent(t *testing.T) {
	h, keys := benchHolder(200)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range 300 {
				i := (n*13 + g) % len(keys)
				source := fmt.Sprintf("10.0.0.%d", i%5)
				got, err := h.MatchFrom(CreateAuthID(keys[i][:], time.Now().Unix()), source)
				if err != nil || got != i {
					t.Errorf("user %d: got %v, %v", i, got, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSourceHintsBounded(t *testing.T) {
	h := newSourceHints()
	item := &AuthIDDecoderItem{}
	for i := range 4 * hintShards * hintsPerGeneration {
		h.put(fmt.Sprintf("s%d", i), item)
	}
	total := 0
	for i := range h.shards {
		total += len(h.shards[i].cur) + len(h.shards[i].prev)
	}
	if max := 2 * hintShards * hintsPerGeneration; total > max {
		t.Fatalf("%d sources remembered, want at most %d", total, max)
	}
}

package shadowsocks

import (
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

// A multi-user AEAD request that misses the caches is matched by trying every
// user, which costs time proportional to the number of users. Clients of
// expired users and probes do this on every attempt. Clients of removed users
// are recognized by their keys (see retiredUsers) and remembered per IP.
// scanLimiter gives each source IP a token bucket that only full scans
// matching nobody spend, so other clients behind a relay are not affected.
// An IP without tokens skips the full scan and only tries its cached users
// and the scanLimitedRecentUsers most recent users.
const (
	// Full scans are not limited below this many keys (users and removed
	// users).
	scanLimitMinUsers = 256

	// Failed full scans an IP can make in a row.
	scanBurst = 8
	// Time to regain one full scan.
	scanRefill = 2 * time.Second

	// Recent users tried by a throttled IP.
	scanLimitedRecentUsers = 64

	scanShards = 32
	// IPs tracked per shard: at most about 130k IPs.
	scanShardCap = 4096
	// Removed users remembered per IP, enough for a relay in front of
	// many expired clients.
	maxRetiredPerIP = 32
)

type scanBucket struct {
	tokens float64
	last   int64 // UnixNano time of tokens

	// removed users whose clients connect from this IP, most recent last
	retired []*protocol.MemoryUser
}

type scanShard struct {
	mu      sync.Mutex
	buckets map[string]*scanBucket
}

type scanLimiter struct {
	shards [scanShards]scanShard
}

func newScanLimiter() *scanLimiter {
	l := &scanLimiter{}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*scanBucket)
	}
	return l
}

func (l *scanLimiter) shard(key string) *scanShard {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &l.shards[h%scanShards]
}

// refilled returns the tokens b has at now.
func (b *scanBucket) refilled(now int64) float64 {
	t := b.tokens + float64(now-b.last)/float64(scanRefill)
	if t > scanBurst {
		t = scanBurst
	}
	return t
}

// Allow reports whether key may make a full scan now.
func (l *scanLimiter) Allow(key string) bool {
	if key == "" {
		return true
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		return true
	}
	return b.refilled(time.Now().UnixNano()) >= 1
}

// Fail records a failed full scan from key.
func (l *scanLimiter) Fail(key string) {
	if key == "" {
		return
	}
	now := time.Now().UnixNano()
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucket(key, now)
	b.tokens = b.refilled(now) - 1
	if b.tokens < 0 {
		b.tokens = 0
	}
	b.last = now
}

// Success forgets the failures of key.
func (l *scanLimiter) Success(key string) {
	if key == "" {
		return
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		return
	}
	if len(b.retired) == 0 {
		delete(s.buckets, key)
		return
	}
	b.tokens = scanBurst // keep the removed users for other clients of the IP
}

// Retired returns the removed users seen from key.
func (l *scanLimiter) Retired(key string) []*protocol.MemoryUser {
	if key == "" {
		return nil
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[key]; ok && len(b.retired) > 0 {
		return slices.Clone(b.retired)
	}
	return nil
}

// AddRetired records that a client of the removed user u connects from key.
// This is not a failure: it does not spend a token.
func (l *scanLimiter) AddRetired(key string, u *protocol.MemoryUser) {
	if key == "" {
		return
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucket(key, time.Now().UnixNano())
	b.retired = slices.DeleteFunc(b.retired, func(r *protocol.MemoryUser) bool { return r == u })
	if len(b.retired) >= maxRetiredPerIP {
		b.retired = slices.Delete(b.retired, 0, len(b.retired)-maxRetiredPerIP+1)
	}
	b.retired = append(b.retired, u)
}

// DropRetired forgets u for key, as it is no longer a removed user.
func (l *scanLimiter) DropRetired(key string, u *protocol.MemoryUser) {
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[key]; ok {
		b.retired = slices.DeleteFunc(b.retired, func(r *protocol.MemoryUser) bool { return r == u })
	}
}

// bucket returns the bucket of key, creating a full one if needed.
// It must be called with s.mu held.
func (s *scanShard) bucket(key string, now int64) *scanBucket {
	b, ok := s.buckets[key]
	if !ok {
		if len(s.buckets) >= scanShardCap {
			s.evict(now)
		}
		b = &scanBucket{tokens: scanBurst, last: now}
		s.buckets[key] = b
	}
	return b
}

// evict makes room in a full shard. It drops buckets that have refilled and
// remember no removed users, which is the same as having no record, then
// random ones if needed. It must be called with s.mu held.
func (s *scanShard) evict(now int64) {
	for k, b := range s.buckets {
		if b.refilled(now) >= scanBurst && len(b.retired) == 0 {
			delete(s.buckets, k)
		}
	}
	for k := range s.buckets {
		if len(s.buckets) < scanShardCap*3/4 {
			break
		}
		delete(s.buckets, k)
	}
}

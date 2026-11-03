package shadowsocks

import (
	"sync"
	"time"
)

// A multi-user AEAD request that misses the caches is matched by trying every
// user, which costs time proportional to the number of users. Clients of
// expired users and probes do this on every attempt. scanLimiter gives each
// source IP a token bucket that only failed full scans spend, so working
// clients are not affected. An IP without tokens skips the full scan and only
// tries its cached users and the scanLimitedRecentUsers most recent users.
const (
	// Full scans are not limited below this many users.
	scanLimitMinUsers = 256

	// Failed full scans an IP can make in a row.
	scanBurst = 8
	// Time to regain one full scan.
	scanRefill = 2 * time.Second

	// Recent users tried by a throttled IP.
	scanLimitedRecentUsers = 64

	scanShards = 32
	// IPs tracked per shard: at most about 130k IPs and 13 MB in total.
	scanShardCap = 4096
)

type scanBucket struct {
	tokens float64
	last   int64 // UnixNano time of tokens
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
	b, ok := s.buckets[key]
	if !ok {
		if len(s.buckets) >= scanShardCap {
			s.evict(now)
		}
		b = &scanBucket{tokens: scanBurst, last: now}
		s.buckets[key] = b
	}
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
	delete(s.buckets, key)
	s.mu.Unlock()
}

// evict makes room in a full shard. It drops buckets that have refilled,
// which is the same as having no record, then random ones if needed.
// It must be called with s.mu held.
func (s *scanShard) evict(now int64) {
	for k, b := range s.buckets {
		if b.refilled(now) >= scanBurst {
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

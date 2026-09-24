package aead

import "sync"

const (
	// maxHintsPerSource is how many recent users are kept per source. A
	// household behind one IP has a few; a relay has many, and gains little
	// from hints either way.
	maxHintsPerSource = 4
	hintShards        = 16
	// hintsPerGeneration bounds each shard's current generation; with the
	// previous one kept, at most 2*hintShards*hintsPerGeneration sources
	// are remembered.
	hintsPerGeneration = 1024
)

// sourceHints remembers which users recently authenticated from each source
// address, most recent first. Each shard keeps two generations of entries:
// when the current one fills, it becomes the previous one and the old
// previous one is dropped, which forgets sources not seen for a while
// without tracking per-entry age.
type sourceHints struct {
	shards [hintShards]hintShard
}

type hintShard struct {
	mu        sync.Mutex
	cur, prev map[string][maxHintsPerSource]*AuthIDDecoderItem
}

func newSourceHints() *sourceHints {
	h := &sourceHints{}
	for i := range h.shards {
		h.shards[i].cur = make(map[string][maxHintsPerSource]*AuthIDDecoderItem)
	}
	return h
}

func (h *sourceHints) shard(source string) *hintShard {
	var x uint32 = 2166136261
	for i := 0; i < len(source); i++ {
		x = (x ^ uint32(source[i])) * 16777619
	}
	return &h.shards[x%hintShards]
}

// get copies source's hints into out and returns how many there are.
func (h *sourceHints) get(source string, out *[maxHintsPerSource]*AuthIDDecoderItem) int {
	s := h.shard(source)
	s.mu.Lock()
	e, ok := s.cur[source]
	if !ok {
		e = s.prev[source]
	}
	s.mu.Unlock()
	n := 0
	for _, item := range e {
		if item != nil {
			out[n] = item
			n++
		}
	}
	return n
}

// put records that item just authenticated from source.
func (h *sourceHints) put(source string, item *AuthIDDecoderItem) {
	s := h.shard(source)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.cur[source]
	if !ok {
		old = s.prev[source]
	}
	if old[0] == item && ok {
		return
	}
	e := [maxHintsPerSource]*AuthIDDecoderItem{item}
	n := 1
	for _, o := range old {
		if o != nil && o != item && !o.removed && n < maxHintsPerSource {
			e[n] = o
			n++
		}
	}
	if !ok && len(s.cur) >= hintsPerGeneration {
		s.prev = s.cur
		s.cur = make(map[string][maxHintsPerSource]*AuthIDDecoderItem, hintsPerGeneration)
	}
	s.cur[source] = e
}

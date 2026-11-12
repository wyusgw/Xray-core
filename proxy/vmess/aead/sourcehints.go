package aead

import "sync"

const (
	maxHintsPerSource  = 4
	hintShards         = 16
	hintsPerGeneration = 1024
)

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

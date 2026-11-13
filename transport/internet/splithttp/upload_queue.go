package splithttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal/done"
)

type Packet struct {
	Reader  *httpServerConn
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	reader        atomic.Pointer[httpServerConn]
	pushedPackets chan Packet
	heap          uploadHeap
	nextSeq       uint64
	maxPackets    int
	closed        *done.Instance

	readMu   sync.Mutex
	readSeq  uint64
	readMore chan struct{}
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		closed:        done.New(),
		maxPackets:    maxPackets,
		readMore:      make(chan struct{}),
	}
}

// Admit blocks until seq is within maxPackets of the next packet to be read, so a
// slow reader leaves the rest of the upload unread on the client side.
func (h *uploadQueue) Admit(ctx context.Context, seq uint64) error {
	for {
		h.readMu.Lock()
		next, more := h.readSeq, h.readMore
		h.readMu.Unlock()
		if seq < next+uint64(h.maxPackets) {
			return nil
		}
		select {
		case <-more:
		case <-ctx.Done():
			return ctx.Err()
		case <-h.closed.Wait():
			return errors.New("packet queue closed")
		}
	}
}

func (h *uploadQueue) advance(next uint64) {
	h.readMu.Lock()
	h.readSeq = next
	close(h.readMore)
	h.readMore = make(chan struct{})
	h.readMu.Unlock()
}

func (h *uploadQueue) Push(p Packet) error {
	if h.reader.Load() != nil || (p.Reader != nil && !h.reader.CompareAndSwap(nil, p.Reader)) {
		return errors.New("h.reader already exists")
	}
	select {
	case h.pushedPackets <- p: // no panic
		if h.closed.Done() {
			return errors.New("packet queue closed")
		}
		return nil
	case <-h.closed.Wait():
		return errors.New("packet queue closed")
	}
}

func (h *uploadQueue) Close() error {
	h.closed.Close()
	if reader := h.reader.Load(); reader != nil {
		return reader.Close()
	}
	return nil
}

func (h *uploadQueue) Read(b []byte) (int, error) {
	if reader := h.reader.Load(); reader != nil {
		return reader.Read(b)
	}

	if h.closed.Done() {
		return 0, io.EOF
	}

	if len(h.heap) == 0 {
		select {
		case p := <-h.pushedPackets:
			if p.Reader != nil {
				return p.Reader.Read(b)
			}
			heap.Push(&h.heap, p)
		case <-h.closed.Wait():
			return 0, io.EOF
		}
	}

	for len(h.heap) > 0 {
		packet := heap.Pop(&h.heap).(Packet)
		n := 0

		if packet.Seq == h.nextSeq {
			copy(b, packet.Payload)
			n = min(len(b), len(packet.Payload))

			if n < len(packet.Payload) {
				// partial read
				packet.Payload = packet.Payload[n:]
				heap.Push(&h.heap, packet)
			} else {
				h.nextSeq = packet.Seq + 1
				h.advance(h.nextSeq)
			}

			return n, nil
		}

		// misordered packet
		if packet.Seq > h.nextSeq {
			if len(h.heap) > h.maxPackets {
				// the "reassembly buffer" is too large, and we want to
				// constrain memory usage somehow. let's tear down the
				// connection, and hope the application retries.
				return 0, errors.New("packet queue is too large")
			}
			heap.Push(&h.heap, packet)
			select {
			case p := <-h.pushedPackets:
				heap.Push(&h.heap, p)
			case <-h.closed.Wait():
				return 0, io.EOF
			}
		}
	}

	return 0, nil
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

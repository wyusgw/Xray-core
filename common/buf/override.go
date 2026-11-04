package buf

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
)

type EndpointOverrideReader struct {
	Reader
	Dest         net.Address
	OriginalDest net.Address
}

func (r *EndpointOverrideReader) ReadMultiBuffer() (MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if err == nil {
		for _, b := range mb {
			if b.UDP != nil && b.UDP.Address == r.OriginalDest {
				b.UDP.Address = r.Dest
			}
		}
	}
	return mb, err
}

// Interrupt implements common.Interruptible.
func (r *EndpointOverrideReader) Interrupt() {
	common.Interrupt(r.Reader)
}

// Close implements io.Closer.
func (r *EndpointOverrideReader) Close() error {
	return common.Close(r.Reader)
}

type EndpointOverrideWriter struct {
	Writer
	Dest         net.Address
	OriginalDest net.Address
}

func (w *EndpointOverrideWriter) WriteMultiBuffer(mb MultiBuffer) error {
	for _, b := range mb {
		if b.UDP != nil && b.UDP.Address == w.Dest {
			b.UDP.Address = w.OriginalDest
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// Interrupt implements common.Interruptible.
func (w *EndpointOverrideWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

// Close implements io.Closer.
func (w *EndpointOverrideWriter) Close() error {
	return common.Close(w.Writer)
}

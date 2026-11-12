package buf_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
)

type closeRecorder struct {
	closed      bool
	interrupted bool
}

func (c *closeRecorder) ReadMultiBuffer() (MultiBuffer, error) {
	return nil, nil
}

func (c *closeRecorder) WriteMultiBuffer(mb MultiBuffer) error {
	ReleaseMulti(mb)
	return nil
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}

func (c *closeRecorder) Interrupt() {
	c.interrupted = true
}

func TestEndpointOverrideReaderClose(t *testing.T) {
	inner := &closeRecorder{}
	r := &EndpointOverrideReader{Reader: inner}
	common.Close(r)
	common.Interrupt(r)
	if !inner.closed || !inner.interrupted {
		t.Error("expected Close() and Interrupt() to reach the inner reader")
	}
}

func TestEndpointOverrideWriterClose(t *testing.T) {
	inner := &closeRecorder{}
	w := &EndpointOverrideWriter{Writer: inner}
	common.Close(w)
	common.Interrupt(w)
	if !inner.closed || !inner.interrupted {
		t.Error("expected Close() and Interrupt() to reach the inner writer")
	}
}

package buf_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
)

type closeProbe struct {
	closed      bool
	interrupted bool
}

func (p *closeProbe) ReadMultiBuffer() (MultiBuffer, error) { return nil, nil }
func (p *closeProbe) WriteMultiBuffer(mb MultiBuffer) error { ReleaseMulti(mb); return nil }
func (p *closeProbe) Close() error                          { p.closed = true; return nil }
func (p *closeProbe) Interrupt()                            { p.interrupted = true }

func TestEndpointOverrideForwardsClose(t *testing.T) {
	w := &closeProbe{}
	common.Close(&EndpointOverrideWriter{Writer: w})
	common.Interrupt(&EndpointOverrideWriter{Writer: w})
	if !w.closed || !w.interrupted {
		t.Fatalf("writer: closed=%v interrupted=%v", w.closed, w.interrupted)
	}

	r := &closeProbe{}
	common.Close(&EndpointOverrideReader{Reader: r})
	common.Interrupt(&EndpointOverrideReader{Reader: r})
	if !r.closed || !r.interrupted {
		t.Fatalf("reader: closed=%v interrupted=%v", r.closed, r.interrupted)
	}
}

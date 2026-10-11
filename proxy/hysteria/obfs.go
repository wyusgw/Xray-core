package hysteria

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
)

const xplusSaltLen = 16

// xplusConn is the packet obfuscation of the first generation: each packet is
// XORed with the SHA-256 of the pre-shared key followed by a per-packet random
// salt, and carries that salt in front of it.
type xplusConn struct {
	net.PacketConn
	key []byte

	// quic-go reads a transport's socket from one goroutine.
	readBuf []byte
}

func newXPlusConn(raw net.PacketConn, password string) net.PacketConn {
	return &xplusConn{PacketConn: raw, key: []byte(password)}
}

// mask XORs payload with the keystream of salt, in place.
func (c *xplusConn) mask(salt, payload []byte) {
	input := make([]byte, 0, len(c.key)+xplusSaltLen)
	input = append(input, c.key...)
	input = append(input, salt...)
	stream := sha256.Sum256(input)
	for i := range payload {
		payload[i] ^= stream[i%sha256.Size]
	}
}

func (c *xplusConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if need := len(p) + xplusSaltLen; len(c.readBuf) < need {
		c.readBuf = make([]byte, need)
	}
	buf := c.readBuf
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= xplusSaltLen {
			continue
		}
		c.mask(buf[:xplusSaltLen], buf[xplusSaltLen:n])
		return copy(p, buf[xplusSaltLen:n]), addr, nil
	}
}

func (c *xplusConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, xplusSaltLen+len(p))
	if _, err := rand.Read(out[:xplusSaltLen]); err != nil {
		return 0, err
	}
	copy(out[xplusSaltLen:], p)
	c.mask(out[:xplusSaltLen], out[xplusSaltLen:])
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

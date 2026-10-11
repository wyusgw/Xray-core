package hysteria

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/errors"
)

// The messages of the first generation, as its reference implementation lays
// them out: big endian, a bool as one byte, a string as a two-byte length
// followed by its bytes.

const maxMessageLength = 0xFFFF

// readClientHello reads the protocol version and the client hello: the rates
// the client can send and receive, in bytes per second, and the secret.
func readClientHello(r io.Reader) (version byte, sendBPS, recvBPS uint64, auth string, err error) {
	var head [1 + 8 + 8 + 2]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, 0, 0, "", err
	}
	secret := make([]byte, binary.BigEndian.Uint16(head[17:19]))
	if _, err = io.ReadFull(r, secret); err != nil {
		return 0, 0, 0, "", err
	}
	return head[0], binary.BigEndian.Uint64(head[1:9]), binary.BigEndian.Uint64(head[9:17]), string(secret), nil
}

// writeServerHello answers the client hello with whether the client was
// accepted, the rates the server can send and receive, and a message.
func writeServerHello(w io.Writer, ok bool, sendBPS, recvBPS uint64, message string) error {
	if len(message) > maxMessageLength {
		return errors.New("message is too long")
	}
	b := make([]byte, 0, 1+8+8+2+len(message))
	if ok {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint64(b, sendBPS)
	b = binary.BigEndian.AppendUint64(b, recvBPS)
	b = binary.BigEndian.AppendUint16(b, uint16(len(message)))
	b = append(b, message...)
	_, err := w.Write(b)
	return err
}

// readRequest reads what a client asks for on a stream: a TCP connection to
// host:port, or, with udp set, a UDP session whose addresses come per message.
func readRequest(r io.Reader) (udp bool, host string, port uint16, err error) {
	var head [1 + 2]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return false, "", 0, err
	}
	name := make([]byte, binary.BigEndian.Uint16(head[1:3]))
	if _, err = io.ReadFull(r, name); err != nil {
		return false, "", 0, err
	}
	var portBytes [2]byte
	if _, err = io.ReadFull(r, portBytes[:]); err != nil {
		return false, "", 0, err
	}
	return head[0] != 0, string(name), binary.BigEndian.Uint16(portBytes[:]), nil
}

// WriteResponse answers a request with whether it was accepted, the UDP
// session it opened, and a message.
func WriteResponse(w io.Writer, ok bool, session uint32, message string) error {
	if len(message) > maxMessageLength {
		return errors.New("message is too long")
	}
	b := make([]byte, 0, 1+4+2+len(message))
	if ok {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint32(b, session)
	b = binary.BigEndian.AppendUint16(b, uint16(len(message)))
	b = append(b, message...)
	_, err := w.Write(b)
	return err
}

// UDPMessage is one datagram of a UDP session, or a fragment of one.
type UDPMessage struct {
	SessionID uint32
	Host      string
	Port      uint16
	MsgID     uint16 // must not be 0 while the message is fragmented
	FragID    uint8
	FragCount uint8 // 1 while the message is whole
	Data      []byte
}

func (m *UDPMessage) headerSize() int {
	return 4 + 2 + len(m.Host) + 2 + 2 + 1 + 1 + 2
}

func (m *UDPMessage) size() int {
	return m.headerSize() + len(m.Data)
}

// serialize writes the message into dst and returns its length, or -1 when dst
// is too small.
func (m *UDPMessage) serialize(dst []byte) int {
	if len(dst) < m.size() {
		return -1
	}
	binary.BigEndian.PutUint32(dst, m.SessionID)
	binary.BigEndian.PutUint16(dst[4:], uint16(len(m.Host)))
	i := 6 + copy(dst[6:], m.Host)
	binary.BigEndian.PutUint16(dst[i:], m.Port)
	binary.BigEndian.PutUint16(dst[i+2:], m.MsgID)
	dst[i+4] = m.FragID
	dst[i+5] = m.FragCount
	binary.BigEndian.PutUint16(dst[i+6:], uint16(len(m.Data)))
	copy(dst[i+8:], m.Data)
	return i + 8 + len(m.Data)
}

func parseUDPMessage(b []byte) (*UDPMessage, error) {
	if len(b) < 6 {
		return nil, errors.New("udp message is too short")
	}
	m := &UDPMessage{SessionID: binary.BigEndian.Uint32(b)}
	hostLen := int(binary.BigEndian.Uint16(b[4:]))
	rest := b[6:]
	if len(rest) < hostLen+2+2+1+1+2 {
		return nil, errors.New("udp message is truncated")
	}
	m.Host = string(rest[:hostLen])
	rest = rest[hostLen:]
	m.Port = binary.BigEndian.Uint16(rest)
	m.MsgID = binary.BigEndian.Uint16(rest[2:])
	m.FragID = rest[4]
	m.FragCount = rest[5]
	dataLen := int(binary.BigEndian.Uint16(rest[6:]))
	rest = rest[8:]
	if len(rest) < dataLen {
		return nil, errors.New("udp message data is truncated")
	}
	m.Data = rest[:dataLen]
	return m, nil
}

// fragment splits m into messages that each fit maxSize.
func fragment(m UDPMessage, maxSize int) []UDPMessage {
	if m.size() <= maxSize {
		return []UDPMessage{m}
	}
	maxPayload := maxSize - m.headerSize()
	if maxPayload <= 0 {
		return nil
	}
	count := (len(m.Data) + maxPayload - 1) / maxPayload
	if count > 0xFF {
		return nil
	}
	frags := make([]UDPMessage, 0, count)
	for off, id := 0, 0; off < len(m.Data); id++ {
		size := min(maxPayload, len(m.Data)-off)
		frag := m
		frag.FragID = uint8(id)
		frag.FragCount = uint8(count)
		frag.Data = m.Data[off : off+size]
		frags = append(frags, frag)
		off += size
	}
	return frags
}

// defragger puts a fragmented message back together; it keeps only the message
// being assembled and drops one a newer message overtakes.
type defragger struct {
	msgID uint16
	frags []*UDPMessage
	count uint8
}

func (d *defragger) feed(m *UDPMessage) *UDPMessage {
	if m.FragCount <= 1 {
		return m
	}
	if m.FragID >= m.FragCount {
		return nil
	}
	if m.MsgID != d.msgID || int(m.FragCount) != len(d.frags) {
		d.msgID = m.MsgID
		d.frags = make([]*UDPMessage, m.FragCount)
		d.count = 1
		d.frags[m.FragID] = m
		return nil
	}
	if d.frags[m.FragID] != nil {
		return nil
	}
	d.frags[m.FragID] = m
	d.count++
	if int(d.count) != len(d.frags) {
		return nil
	}
	var data []byte
	for _, frag := range d.frags {
		data = append(data, frag.Data...)
	}
	whole := *m
	whole.Data = data
	whole.FragID = 0
	whole.FragCount = 1
	return &whole
}

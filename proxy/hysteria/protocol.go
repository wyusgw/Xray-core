package hysteria

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
)

const (
	protocolVersion = 3

	closeCodeProtocol = 1
	closeCodeAuth     = 2

	maxMessageLength = 0xFFFF
)

func writeClientHello(w io.Writer, sendBPS, recvBPS uint64, auth []byte) error {
	if len(auth) > maxMessageLength {
		return newError("auth is too long")
	}
	b := make([]byte, 0, 1+8+8+2+len(auth))
	b = append(b, protocolVersion)
	b = binary.BigEndian.AppendUint64(b, sendBPS)
	b = binary.BigEndian.AppendUint64(b, recvBPS)
	b = binary.BigEndian.AppendUint16(b, uint16(len(auth)))
	b = append(b, auth...)
	_, err := w.Write(b)
	return err
}

func readServerHello(r io.Reader) (ok bool, recvBPS uint64, message string, err error) {
	var head [1 + 8 + 8 + 2]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return false, 0, "", err
	}
	msg := make([]byte, binary.BigEndian.Uint16(head[17:19]))
	if _, err = io.ReadFull(r, msg); err != nil {
		return false, 0, "", err
	}
	return head[0] != 0, binary.BigEndian.Uint64(head[9:17]), string(msg), nil
}

func writeRequest(w io.Writer, udp bool, addr string) error {
	var host string
	var port uint64
	if !udp {
		var portText string
		var err error
		if host, portText, err = net.SplitHostPort(addr); err != nil {
			return err
		}
		if port, err = strconv.ParseUint(portText, 10, 16); err != nil {
			return err
		}
		if len(host) > maxMessageLength {
			return newError("address is too long")
		}
	}
	b := make([]byte, 0, 1+2+len(host)+2)
	if udp {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(host)))
	b = append(b, host...)
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	_, err := w.Write(b)
	return err
}

func readResponse(r io.Reader) (ok bool, session uint32, message string, err error) {
	var head [1 + 4 + 2]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return false, 0, "", err
	}
	msg := make([]byte, binary.BigEndian.Uint16(head[5:7]))
	if _, err = io.ReadFull(r, msg); err != nil {
		return false, 0, "", err
	}
	return head[0] != 0, binary.BigEndian.Uint32(head[1:5]), string(msg), nil
}

type udpMessage struct {
	SessionID uint32
	Host      string
	Port      uint16
	MsgID     uint16 // must not be 0 while the message is fragmented
	FragID    uint8
	FragCount uint8 // 1 while the message is whole
	Data      []byte
}

func (m *udpMessage) headerSize() int {
	return 4 + 2 + len(m.Host) + 2 + 2 + 1 + 1 + 2
}

func (m *udpMessage) size() int {
	return m.headerSize() + len(m.Data)
}

func (m *udpMessage) serialize(dst []byte) int {
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

func parseUDPMessage(b []byte) (*udpMessage, error) {
	if len(b) < 6 {
		return nil, newError("udp message is too short")
	}
	m := &udpMessage{SessionID: binary.BigEndian.Uint32(b)}
	hostLen := int(binary.BigEndian.Uint16(b[4:]))
	rest := b[6:]
	if len(rest) < hostLen+2+2+1+1+2 {
		return nil, newError("udp message is truncated")
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
		return nil, newError("udp message data is truncated")
	}
	m.Data = rest[:dataLen]
	return m, nil
}

func fragment(m udpMessage, maxSize int) []udpMessage {
	if m.size() <= maxSize {
		return []udpMessage{m}
	}
	maxPayload := maxSize - m.headerSize()
	if maxPayload <= 0 {
		return nil
	}
	count := (len(m.Data) + maxPayload - 1) / maxPayload
	if count > 0xFF {
		return nil
	}
	frags := make([]udpMessage, 0, count)
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

type defragger struct {
	msgID uint16
	frags []*udpMessage
	count uint8
}

func (d *defragger) feed(m *udpMessage) *udpMessage {
	if m.FragCount <= 1 {
		return m
	}
	if m.FragID >= m.FragCount {
		return nil
	}
	if m.MsgID != d.msgID || int(m.FragCount) != len(d.frags) {
		d.msgID = m.MsgID
		d.frags = make([]*udpMessage, m.FragCount)
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

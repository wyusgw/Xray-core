package aead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	rand3 "crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"slices"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
)

var (
	ErrNotFound     = errors.New("user do not exist")
	ErrNeagtiveTime = errors.New("timestamp is negative")
	ErrInvalidTime  = errors.New("invalid timestamp, perhaps unsynchronized time")
	ErrReplay       = errors.New("replayed request")
)

func CreateAuthID(cmdKey []byte, time int64) [16]byte {
	buf := bytes.NewBuffer(nil)
	common.Must(binary.Write(buf, binary.BigEndian, time))
	var zero uint32
	common.Must2(io.CopyN(buf, rand3.Reader, 4))
	zero = crc32.ChecksumIEEE(buf.Bytes())
	common.Must(binary.Write(buf, binary.BigEndian, zero))
	aesBlock := NewCipherFromKey(cmdKey)
	if buf.Len() != 16 {
		panic("Size unexpected")
	}
	var result [16]byte
	aesBlock.Encrypt(result[:], buf.Bytes())
	return result
}

func NewCipherFromKey(cmdKey []byte) cipher.Block {
	aesBlock, err := aes.NewCipher(KDF16(cmdKey, KDFSaltConstAuthIDEncryptionKey))
	if err != nil {
		panic(err)
	}
	return aesBlock
}

type AuthIDDecoder struct {
	s cipher.Block
}

func NewAuthIDDecoder(cmdKey []byte) *AuthIDDecoder {
	return &AuthIDDecoder{NewCipherFromKey(cmdKey)}
}

func (aidd *AuthIDDecoder) Decode(data [16]byte) (int64, uint32, int32, []byte) {
	aidd.s.Decrypt(data[:], data[:])
	var t int64
	var zero uint32
	var rand int32
	reader := bytes.NewReader(data[:])
	common.Must(binary.Read(reader, binary.BigEndian, &t))
	common.Must(binary.Read(reader, binary.BigEndian, &rand))
	common.Must(binary.Read(reader, binary.BigEndian, &zero))
	return t, zero, rand, data[:]
}

func NewAuthIDDecoderHolder() *AuthIDDecoderHolder {
	return &AuthIDDecoderHolder{
		index:  make(map[[16]byte]int),
		filter: antireplay.NewMapFilter[[16]byte](120),
		hints:  newSourceHints(),
	}
}

// AuthIDDecoderHolder finds the user an auth ID belongs to. An auth ID is
// encrypted with its user's key and carries no user identifier, so finding
// the user means trying users' keys until one decrypts it to a valid
// checksum. The users a client address matched recently are tried first.
//
// AddUser and RemoveUser must not run concurrently with each other or with
// Match; Match may run concurrently with itself.
type AuthIDDecoderHolder struct {
	items  []*AuthIDDecoderItem
	index  map[[16]byte]int // key -> position in items
	filter *antireplay.ReplayFilter[[16]byte]
	hints  *sourceHints
}

type AuthIDDecoderItem struct {
	dec     *AuthIDDecoder
	ticket  interface{}
	key     [16]byte
	removed bool
}

func NewAuthIDDecoderItem(key [16]byte, ticket interface{}) *AuthIDDecoderItem {
	return &AuthIDDecoderItem{
		dec:    NewAuthIDDecoder(key[:]),
		ticket: ticket,
		key:    key,
	}
}

func (a *AuthIDDecoderHolder) AddUser(key [16]byte, ticket interface{}) {
	item := NewAuthIDDecoderItem(key, ticket)
	if i, ok := a.index[key]; ok {
		a.items[i].removed = true
		a.items[i] = item
		return
	}
	a.index[key] = len(a.items)
	a.items = append(a.items, item)
}

func (a *AuthIDDecoderHolder) RemoveUser(key [16]byte) {
	i, ok := a.index[key]
	if !ok {
		return
	}
	a.items[i].removed = true // stops source hints from still returning it
	last := len(a.items) - 1
	if i != last {
		a.items[i] = a.items[last]
		a.index[a.items[i].key] = i
	}
	a.items[last] = nil
	a.items = a.items[:last]
	delete(a.index, key)
}

// checks reports whether authID decrypts under this item's key to a valid
// checksum, and the timestamp it carries. d is scratch space, passed in so
// that it isn't allocated per call.
func (item *AuthIDDecoderItem) checks(authID, d *[16]byte) (int64, bool) {
	item.dec.s.Decrypt(d[:], authID[:])
	if binary.BigEndian.Uint32(d[12:]) != crc32.ChecksumIEEE(d[:12]) {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(d[:8])), true
}

func (a *AuthIDDecoderHolder) Match(authID [16]byte) (interface{}, error) {
	return a.MatchFrom(authID, "")
}

// MatchFrom is Match for a connection from source (the client's IP, or ""
// if unknown), trying the users that source matched recently first.
func (a *AuthIDDecoderHolder) MatchFrom(authID [16]byte, source string) (interface{}, error) {
	// A wrong key yields a valid checksum by chance once in 2^32 tries, so a
	// match with a bad timestamp can be a false positive: keep looking, and
	// report the timestamp only if no other user matches.
	errNoMatch := ErrNotFound
	var d [16]byte

	var hinted [maxHintsPerSource]*AuthIDDecoderItem
	var nHinted int
	if source != "" {
		nHinted = a.hints.get(source, &hinted)
		for _, item := range hinted[:nHinted] {
			if item.removed {
				continue
			}
			if t, ok := item.checks(&authID, &d); ok {
				if err := checkTime(t); err != nil {
					errNoMatch = err
					continue
				}
				return a.accept(item, authID, source)
			}
		}
	}

	for _, item := range a.items {
		t, ok := item.checks(&authID, &d)
		if !ok || slices.Contains(hinted[:nHinted], item) {
			continue
		}
		if err := checkTime(t); err != nil {
			errNoMatch = err
			continue
		}
		return a.accept(item, authID, source)
	}
	return nil, errNoMatch
}

func (a *AuthIDDecoderHolder) accept(item *AuthIDDecoderItem, authID [16]byte, source string) (interface{}, error) {
	if !a.filter.Check(authID) {
		return nil, ErrReplay
	}
	if source != "" {
		a.hints.put(source, item)
	}
	return item.ticket, nil
}

func checkTime(t int64) error {
	if t < 0 {
		return ErrNeagtiveTime
	}
	if math.Abs(float64(t)-float64(time.Now().Unix())) > 120 {
		return ErrInvalidTime
	}
	return nil
}

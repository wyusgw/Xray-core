package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

var ssSubkeyInfo = []byte("ss-subkey")

// subkeyKDF derives the same subkeys as hkdfSHA1 for one salt and many
// secrets, which is what finding a multi-user connection's user takes: one
// derivation per candidate user. hkdfSHA1 builds two HMACs per call; here
// the salt-keyed extract HMAC is built once and the expand HMAC reuses two
// SHA-1 states, so a derivation allocates nothing.
type subkeyKDF struct {
	extract      hash.Hash // HMAC-SHA1 keyed with the salt
	inner, outer hash.Hash // SHA-1 states for the expand HMAC, keyed with the PRK
	ipad, opad   [sha1.BlockSize]byte
	prk, t       [sha1.Size]byte
	counter      [1]byte
}

func newSubkeyKDF(salt []byte) *subkeyKDF {
	return &subkeyKDF{
		extract: hmac.New(sha1.New, salt),
		inner:   sha1.New(),
		outer:   sha1.New(),
	}
}

// derive writes HKDF-SHA1(secret, salt, "ss-subkey") into out.
func (k *subkeyKDF) derive(secret, out []byte) {
	k.extract.Reset()
	k.extract.Write(secret)
	prk := k.extract.Sum(k.prk[:0])

	// HMAC with a key shorter than the block: the key zero-padded to the
	// block size, XORed with the pads.
	for i := range k.ipad {
		var b byte
		if i < len(prk) {
			b = prk[i]
		}
		k.ipad[i] = b ^ 0x36
		k.opad[i] = b ^ 0x5c
	}

	// T(i) = HMAC(PRK, T(i-1) | info | i), with T(0) empty.
	var prev []byte
	for n := 0; n < len(out); {
		k.counter[0]++
		k.inner.Reset()
		k.inner.Write(k.ipad[:])
		k.inner.Write(prev)
		k.inner.Write(ssSubkeyInfo)
		k.inner.Write(k.counter[:])
		t := k.inner.Sum(k.t[:0])
		k.outer.Reset()
		k.outer.Write(k.opad[:])
		k.outer.Write(t)
		prev = k.outer.Sum(k.t[:0])
		n += copy(out[n:], prev)
	}
	k.counter[0] = 0
}

package shadowsocks

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

var ssSubkeyInfo = []byte("ss-subkey")

type subkeyKDF struct {
	extract      hash.Hash
	inner, outer hash.Hash
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

func (k *subkeyKDF) derive(secret, out []byte) {
	k.extract.Reset()
	k.extract.Write(secret)
	prk := k.extract.Sum(k.prk[:0])

	for i := range k.ipad {
		var b byte
		if i < len(prk) {
			b = prk[i]
		}
		k.ipad[i] = b ^ 0x36
		k.opad[i] = b ^ 0x5c
	}

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

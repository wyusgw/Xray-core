package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSubkeyKDFMatchesHKDF(t *testing.T) {
	for _, saltLen := range []int{16, 24, 32} {
		salt := make([]byte, saltLen)
		rand.Read(salt)
		kdf := newSubkeyKDF(salt)
		for _, keyLen := range []int{16, 24, 32, 41} {
			for range 20 {
				secret := make([]byte, keyLen)
				rand.Read(secret)
				for _, outLen := range []int{16, 20, 24, 32, 45} {
					want := make([]byte, outLen)
					hkdfSHA1(secret, salt, want)
					got := make([]byte, outLen)
					kdf.derive(secret, got)
					if !bytes.Equal(got, want) {
						t.Fatalf("salt %d key %d out %d: got %x, want %x", saltLen, keyLen, outLen, got, want)
					}
				}
			}
		}
	}
}

func BenchmarkSubkeyDerivation(b *testing.B) {
	salt := make([]byte, 16)
	secret := make([]byte, 16)
	out := make([]byte, 16)
	b.Run("hkdfSHA1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hkdfSHA1(secret, salt, out)
		}
	})
	b.Run("subkeyKDF", func(b *testing.B) {
		b.ReportAllocs()
		kdf := newSubkeyKDF(salt)
		for b.Loop() {
			kdf.derive(secret, out)
		}
	})
}

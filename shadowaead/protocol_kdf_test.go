package shadowaead

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func TestLegacyHKDFMatchesKdf(t *testing.T) {
	for _, methodName := range List {
		t.Run(methodName, func(t *testing.T) {
			spec, err := parseMethod(methodName)
			if err != nil {
				t.Fatal(err)
			}
			masterKey := make([]byte, spec.keySaltLength)
			salt := make([]byte, spec.keySaltLength)
			for index := range masterKey {
				masterKey[index] = byte(index*7 + 3)
				salt[index] = byte(index*11 + 5)
			}

			expected := buf.NewSize(spec.keySaltLength)
			defer expected.Release()
			Kdf(masterKey, salt, expected)

			actual := make([]byte, spec.keySaltLength)
			var kdf legacyHKDF
			kdf.Reset(salt)
			kdf.Derive(masterKey, actual)
			if !bytes.Equal(actual, expected.Bytes()) {
				t.Fatalf("legacy HKDF mismatch: got %x, want %x", actual, expected.Bytes())
			}
		})
	}
}

func TestLegacyHKDFDeriveDoesNotAllocate(t *testing.T) {
	var masterKey [maxLegacyKeySize]byte
	var salt [maxLegacyKeySize]byte
	var output [maxLegacyKeySize]byte
	for index := range masterKey {
		masterKey[index] = byte(index + 1)
		salt[index] = byte(index + 33)
	}
	var kdf legacyHKDF
	kdf.Reset(salt[:])

	allocations := testing.AllocsPerRun(1000, func() {
		kdf.Derive(masterKey[:], output[:])
	})
	if allocations != 0 {
		t.Fatalf("legacy HKDF allocated %.2f objects per derivation", allocations)
	}
}

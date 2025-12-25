package base58

import (
	"bytes"
	"testing"
)

// FuzzBase58RoundTrip fuzzes the Encode -> Decode cycle.
func FuzzBase58RoundTrip(f *testing.F) {
	// Seed corpus
	f.Add([]byte("Hello World"))
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := Encode(data)
		decoded := Decode(encoded)

		// Decoded should match original
		if !bytes.Equal(data, decoded) {
			t.Errorf("Roundtrip mismatch: input=%x, encoded=%s, decoded=%x", data, encoded, decoded)
		}
	})
}

// FuzzBase58Decode fuzzes Decode with random strings.
func FuzzBase58Decode(f *testing.F) {
	f.Add("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	f.Add("")
	f.Add("111111")
	f.Add("invalid_chars_0OIl")

	f.Fuzz(func(t *testing.T, input string) {
		// Just ensure it doesn't panic
		_ = Decode(input)
	})
}

// FuzzBase58CheckDecode fuzzes CheckDecode with random strings.
func FuzzBase58CheckDecode(f *testing.F) {
	f.Add("3vQB7B6MrGQZaxCuFg4oh")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		// Just ensure it doesn't panic
		_, _ = CheckDecode(input)
	})
}

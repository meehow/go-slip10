package slip10

import (
	"testing"
)

// FuzzParsePath fuzzes parsing of BIP-32 paths.
func FuzzParsePath(f *testing.F) {
	f.Add("m/0/1/2")
	f.Add("m/44'/0'/0'")
	f.Add("")
	f.Add("m//")
	f.Add("invalid")

	f.Fuzz(func(t *testing.T, path string) {
		_, _ = ParsePath(path)
	})
}

// FuzzNewNodeFromExtendedKey fuzzes parsing of xpub/xpriv keys.
func FuzzNewNodeFromExtendedKey(f *testing.F) {
	// Seed with valid key parts (though full valid key is hard to mock without valid checksum)
	f.Add("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
	f.Add("")
	f.Add("invalid")

	f.Fuzz(func(t *testing.T, key string) {
		// NewNodeFromExtendedKey requires a curve, use Secp256k1 as default
		_, _ = NewNodeFromExtendedKey(key, NewSecp256k1())
	})
}

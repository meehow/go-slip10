package slip10

import (
	"crypto/rand"
	"testing"

	"github.com/meehow/go-slip10/base58"
)

func BenchmarkBase58Encode(b *testing.B) {
	data := make([]byte, 32)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base58.Encode(data)
	}
}

func BenchmarkBase58Decode(b *testing.B) {
	data := make([]byte, 32)
	rand.Read(data)
	encoded := base58.Encode(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base58.Decode(encoded)
	}
}

func BenchmarkMnemonicToSeed(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"
	for i := 0; i < b.N; i++ {
		MnemonicToSeed(mnemonic, passphrase)
	}
}

func BenchmarkNewMasterNode(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	curve := NewSecp256k1()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewMasterNode(seed, curve)
	}
}

func BenchmarkDerive(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	curve := NewSecp256k1()
	node, _ := NewMasterNode(seed, curve)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.Derive(uint32(i))
	}
}

// Curve-specific benchmarks
func BenchmarkDeriveSecp256k1(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewSecp256k1())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.Derive(HardenedOffset + uint32(i))
	}
}

func BenchmarkDeriveNist256p1(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewNist256p1())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.Derive(HardenedOffset + uint32(i))
	}
}

func BenchmarkDeriveEd25519(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewEd25519())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.Derive(HardenedOffset + uint32(i))
	}
}

func BenchmarkDeriveCurve25519(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewCurve25519())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.Derive(HardenedOffset + uint32(i))
	}
}

// Deep derivation path benchmark
func BenchmarkDerivePath(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewSecp256k1())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.DerivePath("m/44'/0'/0'/0/0")
	}
}

// Fingerprint calculation benchmark
func BenchmarkFingerprint(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewSecp256k1())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.Fingerprint()
	}
}

// XPub/XPriv serialization benchmarks
func BenchmarkXPriv(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewSecp256k1())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.XPriv()
	}
}

func BenchmarkXPub(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	node, _ := NewMasterNode(seed, NewSecp256k1())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node.XPub()
	}
}

// ParsePath benchmark
func BenchmarkParsePath(b *testing.B) {
	path := "m/44'/0'/0'/0/0"
	for i := 0; i < b.N; i++ {
		ParsePath(path)
	}
}

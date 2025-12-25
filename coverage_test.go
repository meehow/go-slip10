package slip10

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// mockErrorCurve is a test curve that returns errors to test error paths
type mockErrorCurve struct {
	name          string
	masterKeyErr  error
	derivePrivErr error
	derivePubErr  error
}

func (c *mockErrorCurve) Name() string { return c.name }
func (c *mockErrorCurve) MasterKey(seed []byte) ([]byte, []byte, error) {
	if c.masterKeyErr != nil {
		return nil, nil, c.masterKeyErr
	}
	return make([]byte, 32), make([]byte, 32), nil
}
func (c *mockErrorCurve) DerivePrivateChild(privKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if c.derivePrivErr != nil {
		return nil, nil, c.derivePrivErr
	}
	return make([]byte, 32), make([]byte, 32), nil
}
func (c *mockErrorCurve) DerivePublicChild(pubKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	if c.derivePubErr != nil {
		return nil, nil, c.derivePubErr
	}
	return make([]byte, 33), make([]byte, 32), nil
}
func (c *mockErrorCurve) PublicKey(privKey []byte) []byte {
	return make([]byte, 33)
}

// Tests to achieve 100% coverage

// Test Ed25519 DerivePublicChild returns error (line 34-36 in curves.go)
func TestEd25519DerivePublicChildNotSupported(t *testing.T) {
	curve := NewEd25519()
	_, _, err := curve.DerivePublicChild(nil, nil, 0)
	if err == nil {
		t.Error("expected error for Ed25519 public child derivation")
	}
	if err.Error() != "public child derivation not supported for this curve" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Curve25519 DerivePublicChild returns error (inherits from baseCurve)
func TestCurve25519DerivePublicChildNotSupported(t *testing.T) {
	curve := NewCurve25519()
	_, _, err := curve.DerivePublicChild(nil, nil, 0)
	if err == nil {
		t.Error("expected error for Curve25519 public child derivation")
	}
	if err.Error() != "public child derivation not supported for this curve" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test secp256k1 DerivePublicChild with invalid public key (line 63-64)
func TestSecp256k1DerivePublicChildInvalidKey(t *testing.T) {
	curve := NewSecp256k1()
	invalidPubKey := make([]byte, 33)
	invalidPubKey[0] = 0x02 // Correct prefix but invalid point
	for i := 1; i < 33; i++ {
		invalidPubKey[i] = 0xFF
	}
	chainCode := make([]byte, 32)

	_, _, err := curve.DerivePublicChild(invalidPubKey, chainCode, 0)
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

// Test deriveWeierstrassPublicChild with hardened index (line 115-117)
func TestWeierstrassPublicChildHardenedIndex(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create a public-only node
	pubNode := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
	}

	// Try hardened derivation
	_, err := pubNode.Derive(0x80000000)
	if err == nil {
		t.Error("expected error for hardened derivation from public key")
	}
	if !strings.Contains(err.Error(), "cannot derive hardened child from public") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Ed25519 normal derivation error (line 184-186)
func TestEd25519NormalDerivationNotSupported(t *testing.T) {
	curve := NewEd25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Try normal (non-hardened) derivation - should fail
	_, err := master.Derive(0) // Normal index
	if err == nil {
		t.Error("expected error for normal derivation on Ed25519")
	}
	if !strings.Contains(err.Error(), "normal derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Curve25519 normal derivation error (line 232-234)
func TestCurve25519NormalDerivationNotSupported(t *testing.T) {
	curve := NewCurve25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Try normal (non-hardened) derivation - should fail
	_, err := master.Derive(0) // Normal index
	if err == nil {
		t.Error("expected error for normal derivation on Curve25519")
	}
	if !strings.Contains(err.Error(), "normal derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test XPriv on public node returns empty string (line 286-288)
func TestXPrivOnPublicNode(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create public node from XPub
	pubNode, _ := NewNodeFromExtendedKey(master.XPub(), curve)

	xpriv := pubNode.XPriv()
	if xpriv != "" {
		t.Errorf("expected empty string for XPriv on public node, got %s", xpriv)
	}
}

// Test XPriv with nil Version (line 290-292)
func TestXPrivWithNilVersion(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Set version to nil
	master.Version = nil
	xpriv := master.XPriv()

	// Should use default VersionMainPrivate
	if xpriv == "" {
		t.Error("expected non-empty XPriv")
	}

	// Decode and check version bytes
	decoded, _ := base58CheckDecode(xpriv)
	expectedVersion := []byte{0x04, 0x88, 0xAD, 0xE4}
	if !bytes.Equal(decoded[:4], expectedVersion) {
		t.Errorf("expected version %x, got %x", expectedVersion, decoded[:4])
	}
}

// Test parseIndex with index too large (line 343-345)
func TestParseIndexTooLarge(t *testing.T) {
	// 2147483648 is HardenedOffset, which is >= HardenedOffset
	_, err := ParsePath("m/2147483648")
	if err == nil {
		t.Error("expected error for index too large")
	}
	if !strings.Contains(err.Error(), "index too large") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test parseIndex empty string error
func TestParseIndexEmpty(t *testing.T) {
	// This is caught by "empty segment" check first, but let's verify
	_, err := ParsePath("m//0")
	if err == nil {
		t.Error("expected error for empty segment")
	}
	if !strings.Contains(err.Error(), "empty segment") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test base58Encode with large buffer (line 42-44)
func TestBase58EncodeLargeBuffer(t *testing.T) {
	// Create input large enough to exceed stackBuf (128 bytes after encoding)
	// log(256)/log(58) ≈ 1.37, so we need about 128/1.37 ≈ 93+ bytes of non-zero input
	input := make([]byte, 150)
	for i := range input {
		input[i] = 0xFF
	}

	encoded := base58Encode(input)
	if encoded == "" {
		t.Error("encoded string is empty")
	}

	// Verify round-trip
	decoded := base58Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Error("round-trip failed for large buffer")
	}
}

// Test base58Decode with large buffer (line 105-107)
func TestBase58DecodeLargeBuffer(t *testing.T) {
	// Create a long base58 string
	// We need enough characters to exceed the 128-byte stack buffer
	// Each base58 char contributes about 0.73 bytes, so 200+ chars
	input := strings.Repeat("z", 200) // 'z' is valid base58

	decoded := base58Decode(input)
	if decoded == nil {
		t.Error("decoded is nil for valid input")
	}

	// Verify the decoded length is reasonable
	// 200 * 0.733 ≈ 147 bytes
	if len(decoded) < 100 {
		t.Errorf("decoded length too short: %d", len(decoded))
	}
}

// Test String() with nil Curve
func TestNodeStringNilCurve(t *testing.T) {
	node := &Node{
		Curve:     nil,
		IsPrivate: true,
		Depth:     0,
	}

	str := node.String()
	if str != "Node{curve=, depth=0, private=true}" {
		t.Errorf("unexpected String(): %s", str)
	}
}

// Test DerivePath error propagation (line 204-207)
func TestDerivePathErrorPropagation(t *testing.T) {
	curve := NewEd25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Ed25519 only supports hardened derivation, so m/0 should fail
	_, err := master.DerivePath("m/0")
	if err == nil {
		t.Error("expected error for normal derivation on Ed25519")
	}
	if !strings.Contains(err.Error(), "normal derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test base58 edge case: all zeros input
func TestBase58AllZeros(t *testing.T) {
	input := make([]byte, 10)
	encoded := base58Encode(input)

	// All zeros should encode to all '1's
	expected := "1111111111"
	if encoded != expected {
		t.Errorf("expected %s, got %s", expected, encoded)
	}

	decoded := base58Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Errorf("round-trip failed: got %x, want %x", decoded, input)
	}
}

// Test Derive from public node with unsupported curve (tests public derivation error path)
func TestDerivePublicNodeUnsupportedCurve(t *testing.T) {
	curve := NewEd25519()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create a public-only node (artificially)
	pubNode := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
		Depth:     0,
		ParentFP:  []byte{0, 0, 0, 0},
		Index:     0,
	}

	// Try public derivation - should fail because Ed25519 doesn't support it
	_, err := pubNode.Derive(0)
	if err == nil {
		t.Error("expected error for public derivation on Ed25519")
	}
	if !strings.Contains(err.Error(), "public child derivation not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test secp256k1 public derivation works correctly
func TestSecp256k1PublicDerivation(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Derive child privately
	childPriv, _ := master.Derive(0)

	// Create public-only parent
	pubParent := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
		Depth:     0,
		ParentFP:  []byte{0, 0, 0, 0},
		Index:     0,
	}

	// Derive the same child publicly
	childPub, err := pubParent.Derive(0)
	if err != nil {
		t.Fatalf("public derivation failed: %v", err)
	}

	// Public keys should match
	if !bytes.Equal(childPub.PubKey, childPriv.PubKey) {
		t.Errorf("public keys don't match:\npub:  %x\npriv: %x", childPub.PubKey, childPriv.PubKey)
	}
}

// Test NewNodeFromExtendedKey with testnet xpriv
func TestNewNodeFromExtendedKeyTestnet(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create testnet version
	master.Version = []byte{0x04, 0x35, 0x83, 0x94} // tprv

	// Export and reimport
	xpriv := master.XPriv()
	node, err := NewNodeFromExtendedKey(xpriv, curve)
	if err != nil {
		t.Fatalf("failed to parse testnet xpriv: %v", err)
	}

	if !node.IsPrivate {
		t.Error("expected private node")
	}

	if !bytes.Equal(node.Version, []byte{0x04, 0x35, 0x83, 0x94}) {
		t.Errorf("unexpected version: %x", node.Version)
	}
}

// Note: TestNewNodeFromExtendedKeyInvalidPublicKeyLength is not included because
// the error path at line 118-119 (invalid public key length) is unreachable.
// The payload length is fixed at 78 bytes, and keyOffset is fixed, so
// actualKeyData is always exactly 33 bytes.

// Test base58 with input that causes the i < 0 check
// This is extremely defensive code - let's verify the algorithm works
// even with edge case inputs
func TestBase58EdgeCases(t *testing.T) {
	// Test single byte values
	for i := 0; i < 256; i++ {
		input := []byte{byte(i)}
		encoded := base58Encode(input)
		decoded := base58Decode(encoded)
		if !bytes.Equal(decoded, input) {
			t.Errorf("round-trip failed for byte %d", i)
		}
	}

	// Test with maximum leading zeros followed by data
	input := make([]byte, 50)
	input[49] = 0xFF
	encoded := base58Encode(input)
	decoded := base58Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Error("round-trip failed for leading zeros test")
	}
}

// Test that covers more base58 decode paths
func TestBase58DecodeEdgeCases(t *testing.T) {
	// Single character decode
	decoded := base58Decode("2")
	if len(decoded) != 1 || decoded[0] != 1 {
		t.Errorf("expected [1], got %v", decoded)
	}

	// Mix of leading 1s and other chars
	decoded = base58Decode("111z")
	expected := []byte{0, 0, 0, 57}
	if !bytes.Equal(decoded, expected) {
		t.Errorf("expected %v, got %v", expected, decoded)
	}
}

// Test that covers parseIndex with just a hardened marker and no number
func TestParseIndexJustHardenedMarker(t *testing.T) {
	_, err := ParsePath("m/'")
	if err == nil {
		t.Error("expected error for path with just hardened marker")
	}
}

// Test NewMasterNode with curves that could theoretically error
// (Though in practice, ed25519/curve25519 MasterKey never errors)
func TestNewMasterNodeAllCurves(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	curves := []Curve{
		NewSecp256k1(),
		NewNist256p1(),
		NewEd25519(),
		NewCurve25519(),
	}

	for _, curve := range curves {
		node, err := NewMasterNode(seed, curve)
		if err != nil {
			t.Errorf("NewMasterNode failed for %s: %v", curve.Name(), err)
		}
		if node == nil {
			t.Errorf("node is nil for %s", curve.Name())
		}
		if !node.IsPrivate {
			t.Errorf("expected private node for %s", curve.Name())
		}
	}
}

// Test NewMasterNode error path using mock curve (line 66-67)
func TestNewMasterNodeError(t *testing.T) {
	curve := &mockErrorCurve{
		name:         "mock",
		masterKeyErr: errors.New("master key generation failed"),
	}

	_, err := NewMasterNode([]byte("seed"), curve)
	if err == nil {
		t.Error("expected error from NewMasterNode")
	}
	if err.Error() != "master key generation failed" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test Derive private child error path (line 159-161)
func TestDerivePrivateChildError(t *testing.T) {
	curve := &mockErrorCurve{
		name:          "mock",
		derivePrivErr: errors.New("private derivation failed"),
	}

	node := &Node{
		Curve:     curve,
		IsPrivate: true,
		PrivKey:   make([]byte, 32),
		PubKey:    make([]byte, 33),
		ChainCode: make([]byte, 32),
		Depth:     0,
		ParentFP:  []byte{0, 0, 0, 0},
		Index:     0,
	}

	_, err := node.Derive(0x80000000)
	if err == nil {
		t.Error("expected error from Derive")
	}
	if err.Error() != "private derivation failed" {
		t.Errorf("unexpected error: %v", err)
	}
}

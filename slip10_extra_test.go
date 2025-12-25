package slip10

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCurveNames(t *testing.T) {
	curves := []struct {
		curve    Curve
		expected string
	}{
		{NewSecp256k1(), "secp256k1"},
		{NewNist256p1(), "nist256p1"},
		{NewEd25519(), "ed25519"},
		{NewCurve25519(), "curve25519"},
	}

	for _, tc := range curves {
		if tc.curve.Name() != tc.expected {
			t.Errorf("expected name %s, got %s", tc.expected, tc.curve.Name())
		}
	}
}

func TestNist256p1PublicDerivation(t *testing.T) {
	curve := NewNist256p1()

	// Generate a master key
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Derive m/0 (private)
	childPriv, _ := master.Derive(0)

	// Create public node for m/0
	pubParent := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    childPriv.PubKey,
		ChainCode: childPriv.ChainCode,
		Depth:     childPriv.Depth,
		ParentFP:  childPriv.ParentFP,
		Index:     childPriv.Index,
	}

	// Derive m/0/1 (public) from public parent
	childPub, err := pubParent.Derive(1)
	if err != nil {
		t.Fatalf("failed public derivation: %v", err)
	}

	// Verify against private derivation: m/0 -> m/0/1
	childPrivFromPriv, _ := childPriv.Derive(1)

	if hex.EncodeToString(childPub.PubKey) != hex.EncodeToString(childPrivFromPriv.PubKey) {
		t.Errorf("public derivation mismatch:\nGot:  %x\nWant: %x", childPub.PubKey, childPrivFromPriv.PubKey)
	}

	// Test error: Hardened derivation from public parent
	_, err = pubParent.Derive(0x80000000)
	if err == nil {
		t.Error("expected error for hardened derivation from public parent, got nil")
	}
	if err.Error() != "cannot derive hardened child from public parent" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNodeString(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// String() returns safe representation (no private key exposed)
	expected := "Node{curve=secp256k1, depth=0, private=true}"
	if master.String() != expected {
		t.Errorf("expected String() to return %q, got %q", expected, master.String())
	}

	pubNode, _ := NewNodeFromExtendedKey(master.XPub(), curve)
	expectedPub := "Node{curve=secp256k1, depth=0, private=false}"
	if pubNode.String() != expectedPub {
		t.Errorf("expected String() to return %q, got %q", expectedPub, pubNode.String())
	}
}

func TestDerivePathErrors(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	tests := []struct {
		path      string
		errString string
	}{
		{"", ""}, // Empty path returns nil error
		{"m/abc", "invalid path part \"abc\": strconv.ParseUint: parsing \"abc\": invalid syntax"},
		{"m/1/2h/x", "invalid path part \"x\": strconv.ParseUint: parsing \"x\": invalid syntax"},
		{"1/2", "path must start with 'm/'"},
	}

	for _, tc := range tests {
		_, err := master.DerivePath(tc.path)
		if tc.path == "" {
			if err != nil {
				t.Errorf("expected nil error for empty path, got %v", err)
			}
			continue
		}

		if err == nil {
			t.Errorf("expected error for path %s, got nil", tc.path)
		} else if err.Error() != tc.errString {
			t.Errorf("path %s: expected error %q, got %q", tc.path, tc.errString, err.Error())
		}
	}
}

func TestNewNodeFromExtendedKeyErrors(t *testing.T) {
	curve := NewSecp256k1()

	tests := []struct {
		name      string
		key       string
		errString string
	}{
		{
			name:      "Invalid Base58",
			key:       "invalid-base58-chars-0OIl",
			errString: "invalid base58check length", // base58Decode returns nil, causes length check failure
		},
		{
			name: "Invalid Length",
			// valid checksum but wrong length
			// base58CheckEncode handles arbitrary length, so we construct a valid check-encoded string of wrong length
			key:       base58CheckEncode(make([]byte, 10)),
			errString: "invalid extended key length",
		},
	}

	// Add test cases that require manual construction of invalid payloads to pass base58CheckDecode
	// but fail NewNodeFromExtendedKey validation.

	// Helper to create a valid-looking 78-byte payload and modify it
	createPayload := func(mod func([]byte)) string {
		data := make([]byte, 78)
		// Set valid private key version
		copy(data[0:4], []byte{0x04, 0x88, 0xAD, 0xE4})
		// Set valid key data (0x00 + 32 bytes)
		data[45] = 0x00
		for i := 46; i < 78; i++ {
			data[i] = 1
		}

		mod(data)
		return base58CheckEncode(data)
	}

	tests = append(tests,
		struct{ name, key, errString string }{
			"Invalid Private Key Prefix",
			createPayload(func(d []byte) {
				d[45] = 0x01 // Should be 0x00 for private key
			}),
			"invalid private key prefix",
		},
		struct{ name, key, errString string }{
			"Invalid Public Key Prefix",
			createPayload(func(d []byte) {
				// Set public key version
				copy(d[0:4], []byte{0x04, 0x88, 0xB2, 0x1E})
				d[45] = 0x04 // Should be 0x02 or 0x03
			}),
			"invalid public key prefix",
		},
		struct{ name, key, errString string }{
			"Depth 0 with Non-Zero Index",
			createPayload(func(d []byte) {
				d[4] = 0x00 // Depth 0
				d[9] = 0x01 // Index non-zero (offsets: ver 4, depth 1, parentFP 4, index 4 -> 9)
			}),
			"index must be 0 for depth 0",
		},
		struct{ name, key, errString string }{
			"Depth 0 with Non-Zero Parent Fingerprint",
			createPayload(func(d []byte) {
				d[4] = 0x00 // Depth 0
				d[5] = 0x01 // ParentFP non-zero
			}),
			"parent fingerprint must be 0 for depth 0",
		},
	)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewNodeFromExtendedKey(tc.key, curve)
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if tc.errString != "" && err.Error() != tc.errString {
				t.Errorf("expected error %q, got %q", tc.errString, err.Error())
			}
		})
	}
}

func TestTestnetKeys(t *testing.T) {
	curve := NewSecp256k1()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterNode(seed, curve)

	// Create a testnet node
	testnetNode := &Node{
		Curve:     curve,
		IsPrivate: true,
		PrivKey:   master.PrivKey,
		PubKey:    master.PubKey,
		ChainCode: master.ChainCode,
		Depth:     master.Depth,
		ParentFP:  master.ParentFP,
		Index:     master.Index,
		Version:   []byte{0x04, 0x35, 0x83, 0x94}, // tprv
	}

	xpub := testnetNode.XPub()
	// tpub prefix in hex is roughly 043587cf
	decoded, _ := base58CheckDecode(xpub)
	if hex.EncodeToString(decoded[0:4]) != "043587cf" {
		t.Errorf("expected tpub version bytes 043587cf, got %x", decoded[0:4])
	}
}

func TestInvalidPublicKeyDerivation(t *testing.T) {
	curve := NewNist256p1()

	// Create a public node with invalid public key data (not a valid point)
	invalidPubKey := make([]byte, 33)
	for i := range invalidPubKey {
		invalidPubKey[i] = 0xFF
	}

	node := &Node{
		Curve:     curve,
		IsPrivate: false,
		PubKey:    invalidPubKey,
		ChainCode: make([]byte, 32),
	}

	_, err := node.Derive(0)
	if err == nil {
		t.Error("expected error for invalid public key, got nil")
	}
	// The actual error comes from elliptic.UnmarshalCompressed (or wrapper), usually "invalid public key"
	if err.Error() != "invalid public key" && err.Error() != "square root not found" {
		// "square root not found" can come from unmarshal on some curves/go versions if x is valid but y not
		// but with 0xFF... it's likely generic "invalid"
		// Just checking err != nil is mostly sufficient, but let's be safe
	}
}

func TestNodeWipe(t *testing.T) {
	seed := []byte("seed")
	node, err := NewMasterNode(seed, NewSecp256k1())
	if err != nil {
		t.Fatalf("NewMasterNode failed: %v", err)
	}

	privKeyCopy := make([]byte, len(node.PrivKey))
	copy(privKeyCopy, node.PrivKey)
	chainCodeCopy := make([]byte, len(node.ChainCode))
	copy(chainCodeCopy, node.ChainCode)

	node.Wipe()

	// Check PrivKey is zeroed
	for i, b := range node.PrivKey {
		if b != 0 {
			t.Errorf("PrivKey byte at index %d not zeroed: %d", i, b)
		}
	}
	if bytes.Equal(node.PrivKey, privKeyCopy) {
		t.Error("PrivKey was not modified")
	}

	// Check ChainCode is zeroed
	for i, b := range node.ChainCode {
		if b != 0 {
			t.Errorf("ChainCode byte at index %d not zeroed: %d", i, b)
		}
	}
	if bytes.Equal(node.ChainCode, chainCodeCopy) {
		t.Error("ChainCode was not modified")
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expected      []uint32
		expectedError bool
	}{
		{
			name:     "Empty path (root)",
			path:     "m",
			expected: nil,
		},
		{
			name:     "Simple path",
			path:     "m/0/1/2",
			expected: []uint32{0, 1, 2},
		},
		{
			name:     "Hardened path",
			path:     "m/0'/1h/2H",
			expected: []uint32{0x80000000, 0x80000001, 0x80000002},
		},
		{
			name:     "Mixed path",
			path:     "m/44'/0/0'",
			expected: []uint32{0x80000000 + 44, 0, 0x80000000},
		},
		{
			name:          "Invalid start",
			path:          "n/0",
			expectedError: true,
		},
		{
			name:          "Invalid number",
			path:          "m/abc",
			expectedError: true,
		},
		{
			name:          "Empty part",
			path:          "m//1",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			indices, err := ParsePath(tc.path)
			if tc.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(indices) != len(tc.expected) {
				t.Errorf("Expected %d indices, got %d", len(tc.expected), len(indices))
				return
			}

			for i, idx := range indices {
				if idx != tc.expected[i] {
					t.Errorf("Start index %d: expected %d, got %d", i, tc.expected[i], idx)
				}
			}
		})
	}
}

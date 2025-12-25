package base58

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBase58(t *testing.T) {
	// Test vectors from RFC draft or similar standard sources
	var tests = []struct {
		data string // Hex encoded data
		enc  string // Base58 encoded string
	}{
		{"", ""},
		{"61", "2g"},       // 'a'
		{"626262", "a3gV"}, // "bbb"
		{"636363", "aPEr"}, // "ccc"
		{"00000000000000000000", "1111111111"},
		{"0061", "12g"},
		{"00", "1"},
		// "Hello World" -> "JxF12TrwUP45BMd"
		{"48656c6c6f20576f726c64", "JxF12TrwUP45BMd"},
	}

	for _, test := range tests {
		data, _ := hex.DecodeString(test.data)
		got := Encode(data)
		if got != test.enc {
			t.Errorf("Encode(%x): got %s, want %s", data, got, test.enc)
		}

		decoded := Decode(test.enc)
		if !bytes.Equal(decoded, data) {
			t.Errorf("Decode(%s): got %x, want %x", test.enc, decoded, data)
		}
	}
}

func TestBase58Check(t *testing.T) {
	data := []byte("Hello World")
	encoded := CheckEncode(data)
	decoded, err := CheckDecode(encoded)
	if err != nil {
		t.Fatalf("CheckDecode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Check mismatch: got %s, want %s", decoded, data)
	}

	// Test invalid checksum
	// Mutate the last char
	invalidEncoded := encoded[:len(encoded)-1] + "1"
	_, err = CheckDecode(invalidEncoded)
	if err == nil {
		t.Error("expected error for invalid checksum, got nil")
	}

	// Test invalid length
	_, err = CheckDecode("123")
	if err == nil {
		t.Error("expected error for short payload, got nil")
	}
}

func TestBase58CheckLargePayload(t *testing.T) {
	// Create a payload larger than 128 bytes - 4 bytes checksum = 124 bytes
	// to trigger the make([]byte) path in CheckEncode
	payload := make([]byte, 150)
	for i := range payload {
		payload[i] = byte(i)
	}

	encoded := CheckEncode(payload)
	if len(encoded) == 0 {
		t.Error("encoded string is empty")
	}

	decoded, err := CheckDecode(encoded)
	if err != nil {
		t.Fatalf("failed to decode large payload: %v", err)
	}

	if !bytes.Equal(decoded, payload) {
		t.Error("decoded payload does not match original")
	}
}

func TestBase58InvalidInput(t *testing.T) {
	invalid := "0" // '0' is not in base58 alphabet
	decoded := Decode(invalid)
	if decoded != nil {
		t.Errorf("expected nil for invalid character, got %v", decoded)
	}
}

// Test Encode with large buffer (moved from coverage_test.go)
func TestBase58EncodeLargeBuffer(t *testing.T) {
	// Create input large enough to exceed stackBuf (128 bytes after encoding)
	// log(256)/log(58) ≈ 1.37, so we need about 128/1.37 ≈ 93+ bytes of non-zero input
	input := make([]byte, 150)
	for i := range input {
		input[i] = 0xFF
	}

	encoded := Encode(input)
	if encoded == "" {
		t.Error("encoded string is empty")
	}

	// Verify round-trip
	decoded := Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Error("round-trip failed for large buffer")
	}
}

// Test Decode with large buffer (moved from coverage_test.go)
func TestBase58DecodeLargeBuffer(t *testing.T) {
	// Create a long base58 string
	// We need enough characters to exceed the 128-byte stack buffer
	// Each base58 char contributes about 0.73 bytes, so 200+ chars
	input := strings.Repeat("z", 200) // 'z' is valid base58

	decoded := Decode(input)
	if decoded == nil {
		t.Error("decoded is nil for valid input")
	}

	// Verify the decoded length is reasonable
	// 200 * 0.733 ≈ 147 bytes
	if len(decoded) < 100 {
		t.Errorf("decoded length too short: %d", len(decoded))
	}
}

// Test base58 edge case: all zeros input (moved from coverage_test.go)
func TestBase58AllZeros(t *testing.T) {
	input := make([]byte, 10)
	encoded := Encode(input)

	// All zeros should encode to all '1's
	expected := "1111111111"
	if encoded != expected {
		t.Errorf("expected %s, got %s", expected, encoded)
	}

	decoded := Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Errorf("round-trip failed: got %x, want %x", decoded, input)
	}
}

// Test that covers more base58 decode paths (moved from coverage_test.go)
func TestBase58EdgeCases(t *testing.T) {
	// Test single byte values
	for i := 0; i < 256; i++ {
		input := []byte{byte(i)}
		encoded := Encode(input)
		decoded := Decode(encoded)
		if !bytes.Equal(decoded, input) {
			t.Errorf("round-trip failed for byte %d", i)
		}
	}

	// Test with maximum leading zeros followed by data
	input := make([]byte, 50)
	input[49] = 0xFF
	encoded := Encode(input)
	decoded := Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Error("round-trip failed for leading zeros test")
	}
}

// Test that covers more base58 decode paths (moved from coverage_test.go)
func TestBase58DecodeEdgeCases(t *testing.T) {
	// Single character decode
	decoded := Decode("2")
	if len(decoded) != 1 || decoded[0] != 1 {
		t.Errorf("expected [1], got %v", decoded)
	}

	// Mix of leading 1s and other chars
	decoded = Decode("111z")
	expected := []byte{0, 0, 0, 57}
	if !bytes.Equal(decoded, expected) {
		t.Errorf("expected %v, got %v", expected, decoded)
	}
}

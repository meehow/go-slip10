package slip10

import (
	"bytes"
	"encoding/hex"
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
		got := base58Encode(data)
		if got != test.enc {
			t.Errorf("base58Encode(%x): got %s, want %s", data, got, test.enc)
		}

		decoded := base58Decode(test.enc)
		if !bytes.Equal(decoded, data) {
			t.Errorf("base58Decode(%s): got %x, want %x", test.enc, decoded, data)
		}
	}
}

func TestBase58Check(t *testing.T) {
	data := []byte("Hello World")
	encoded := base58CheckEncode(data)
	decoded, err := base58CheckDecode(encoded)
	if err != nil {
		t.Fatalf("base58CheckDecode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("base58Check mismatch: got %s, want %s", decoded, data)
	}

	// Test invalid checksum
	// Mutate the last char
	invalidEncoded := encoded[:len(encoded)-1] + "1"
	_, err = base58CheckDecode(invalidEncoded)
	if err == nil {
		t.Error("expected error for invalid checksum, got nil")
	}

	// Test invalid length
	_, err = base58CheckDecode("123")
	if err == nil {
		t.Error("expected error for short payload, got nil")
	}
}

func TestBase58CheckLargePayload(t *testing.T) {
	// Create a payload larger than 128 bytes - 4 bytes checksum = 124 bytes
	// to trigger the make([]byte) path in base58CheckEncode
	payload := make([]byte, 150)
	for i := range payload {
		payload[i] = byte(i)
	}

	encoded := base58CheckEncode(payload)
	if len(encoded) == 0 {
		t.Error("encoded string is empty")
	}

	decoded, err := base58CheckDecode(encoded)
	if err != nil {
		t.Fatalf("failed to decode large payload: %v", err)
	}

	if !bytes.Equal(decoded, payload) {
		t.Error("decoded payload does not match original")
	}
}

func TestBase58InvalidInput(t *testing.T) {
	invalid := "0" // '0' is not in base58 alphabet
	decoded := base58Decode(invalid)
	if decoded != nil {
		t.Errorf("expected nil for invalid character, got %v", decoded)
	}
}

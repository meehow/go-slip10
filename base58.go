package slip10

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var decodeMap [256]int8

func init() {
	for i := 0; i < 256; i++ {
		decodeMap[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		decodeMap[base58Alphabet[i]] = int8(i)
	}
}

// base58Encode encodes a byte slice into a Base58 string.
func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Count leading zeros
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// Calculate size: log(256) / log(58) approx 1.37
	size := (len(input)-zeros)*137/100 + 1

	// Use stack buffer if small enough, otherwise allocate
	var stackBuf [128]byte
	var buf []byte
	if size <= len(stackBuf) {
		buf = stackBuf[:size]
	} else {
		buf = make([]byte, size)
	}

	// Ensure buffer is clean
	for i := range buf {
		buf[i] = 0
	}

	// Process the bytes
	idx := size - 1
	for _, b := range input[zeros:] {
		carry := int(b)
		for i := size - 1; i >= idx || carry > 0; i-- {
			if i < 0 {
				break
			}
			carry += 256 * int(buf[i])
			buf[i] = byte(carry % 58)
			carry /= 58
			if i < idx {
				idx = i
			}
		}
	}

	// Skip leading zeros in buf
	skip := 0
	for skip < size && buf[skip] == 0 {
		skip++
	}

	// Translate to base58 alphabet
	n := zeros + (size - skip)
	res := make([]byte, n)
	for i := 0; i < zeros; i++ {
		res[i] = '1'
	}
	for i := 0; i < size-skip; i++ {
		res[zeros+i] = base58Alphabet[buf[skip+i]]
	}

	return string(res)
}

// base58Decode decodes a Base58 string into a byte slice.
func base58Decode(input string) []byte {
	if len(input) == 0 {
		return nil
	}

	zeros := 0
	for i := 0; i < len(input) && input[i] == '1'; i++ {
		zeros++
	}

	// log(58) / log(256) approx 0.73
	size := (len(input)-zeros)*733/1000 + 1

	var stackBuf [128]byte
	var buf []byte
	if size <= len(stackBuf) {
		buf = stackBuf[:size]
	} else {
		buf = make([]byte, size)
	}
	for i := range buf {
		buf[i] = 0
	}

	idx := size - 1

	for _, b := range []byte(input[zeros:]) {
		charIndex := decodeMap[b]
		if charIndex == -1 {
			return nil
		}
		carry := int(charIndex)

		for i := size - 1; i >= idx || carry > 0; i-- {
			if i < 0 {
				break
			}
			carry += 58 * int(buf[i])
			buf[i] = byte(carry)
			carry >>= 8
			if i < idx {
				idx = i
			}
		}
	}

	skip := 0
	for skip < size && buf[skip] == 0 {
		skip++
	}

	res := make([]byte, zeros+(size-skip))
	for i := 0; i < size-skip; i++ {
		res[zeros+i] = buf[skip+i]
	}

	return res
}

// base58CheckEncode encodes a byte slice into a Base58Check string.
func base58CheckEncode(input []byte) string {
	h1 := sha256.Sum256(input)
	h2 := sha256.Sum256(h1[:])

	var buf [128]byte
	if len(input)+4 <= len(buf) {
		copy(buf[:], input)
		copy(buf[len(input):], h2[:4])
		return base58Encode(buf[:len(input)+4])
	}

	combined := make([]byte, len(input)+4)
	copy(combined, input)
	copy(combined[len(input):], h2[:4])
	return base58Encode(combined)
}

// base58CheckDecode decodes a Base58Check string into a byte slice.
func base58CheckDecode(input string) ([]byte, error) {
	decoded := base58Decode(input)
	if len(decoded) < 4 {
		return nil, errors.New("invalid base58check length")
	}

	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])

	if !bytes.Equal(checksum, h2[:4]) {
		return nil, errors.New("invalid checksum")
	}

	return payload, nil
}

package slip10

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

// MnemonicToSeed converts a BIP-39 mnemonic and an optional passphrase into a 512-bit binary seed.
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	password := []byte(norm.NFKD.String(mnemonic))
	salt := []byte("mnemonic" + norm.NFKD.String(passphrase))
	return pbkdf2.Key(password, salt, 2048, 64, sha512.New)
}

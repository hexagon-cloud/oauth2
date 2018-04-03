package sha256

import (
	"crypto/sha256"
	"hash"
	"crypto/hmac"
	"encoding/hex"
)

// NewPasswordEncoder new PasswordEncoder
func NewPasswordEncoder(secret string) *PasswordEncoder {
	key := []byte(secret)
	return &PasswordEncoder{
		hash: hmac.New(sha256.New, key),
	}
}

// PasswordEncoder password encoder uses SHA-256 hashing
type PasswordEncoder struct {
	hash hash.Hash
}

func (spe *PasswordEncoder) Encode(rawPassword string) string {
	spe.hash.Reset()
	spe.hash.Write([]byte(rawPassword))
	return hex.EncodeToString(spe.hash.Sum(nil))
}

func (spe *PasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	spe.hash.Reset()
	spe.hash.Write([]byte(rawPassword))
	if hex.EncodeToString(spe.hash.Sum(nil)) == encodedPassword {
		return true
	}
	return false
}


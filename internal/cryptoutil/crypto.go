// Package cryptoutil owns credential encryption, secure identifiers and password hashes.
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Vault encrypts records using AES-256-GCM and binds each ciphertext to its purpose.
// The master key is copied into the cipher and never retained as a caller-owned slice.
type Vault struct{ aead cipher.AEAD }

func New(master []byte) (*Vault, error) {
	if len(master) != 32 {
		return nil, errors.New("master key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

func (v *Vault) Encrypt(plaintext []byte, purpose string) ([]byte, error) {
	if v == nil || v.aead == nil || purpose == "" {
		return nil, errors.New("vault and record purpose are required")
	}
	// Version precedes the nonce; changing it is rejected before opening the envelope.
	buf := make([]byte, 1+v.aead.NonceSize(), 1+v.aead.NonceSize()+len(plaintext)+v.aead.Overhead())
	buf[0] = 1
	if _, err := rand.Read(buf[1:]); err != nil {
		return nil, err
	}
	return v.aead.Seal(buf, buf[1:], plaintext, []byte(purpose)), nil
}

func (v *Vault) Decrypt(ciphertext []byte, purpose string) ([]byte, error) {
	if v == nil || v.aead == nil || purpose == "" {
		return nil, errors.New("vault and record purpose are required")
	}
	if len(ciphertext) < 1+v.aead.NonceSize()+v.aead.Overhead() || ciphertext[0] != 1 {
		return nil, errors.New("invalid encrypted credential")
	}
	n := 1 + v.aead.NonceSize()
	plaintext, err := v.aead.Open(nil, ciphertext[1:n], ciphertext[n:], []byte(purpose))
	if err != nil {
		return nil, errors.New("credential authentication failed")
	}
	return plaintext, nil
}

func GenerateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "llmgw_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// RandomID panics if the operating system's cryptographic randomness source fails.
// A failure cannot safely be recovered by generating a weaker identifier.
func RandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("secure random source unavailable")
	}
	return hex.EncodeToString(b)
}

const passwordMemory uint32 = 64 * 1024
const passwordTime uint32 = 3
const passwordThreads uint8 = 2

func HashPassword(password string) (string, error) {
	if len(password) == 0 || len(password) > 1024 {
		return "", errors.New("password must contain 1 to 1024 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, passwordThreads, 32)
	defer clear(key)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", passwordMemory, passwordTime, passwordThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, password string) bool {
	// Bound all attacker-controlled work before decoding or allocating the KDF memory.
	if len(encoded) > 512 || len(password) == 0 || len(password) > 1024 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false
	}
	parse := func(s, prefix string) (uint64, error) {
		if !strings.HasPrefix(s, prefix) {
			return 0, errors.New("invalid parameter")
		}
		return strconv.ParseUint(strings.TrimPrefix(s, prefix), 10, 32)
	}
	m, err := parse(params[0], "m=")
	if err != nil || m < 8*1024 || m > 128*1024 {
		return false
	}
	t, err := parse(params[1], "t=")
	if err != nil || t < 1 || t > 5 {
		return false
	}
	p, err := parse(params[2], "p=")
	if err != nil || p < 1 || p > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(p), 32)
	defer clear(got)
	return subtle.ConstantTimeCompare(got, want) == 1
}

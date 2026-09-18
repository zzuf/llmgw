package backup

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"llmgw/internal/cryptoutil"
)

const portableMagic = "LLMGWBP1"
const pendingMagic = "LLMGWST1"
const maxArchiveSize int64 = 512 << 20

// Reserve room for either envelope, including the portable master key, salt,
// nonce and authentication tag. A backup we create must also be restorable.
const maxSnapshotSize = maxArchiveSize - 128

var ErrInvalidBackup = errors.New("invalid or unsupported backup")
var ErrInvalidPassphrase = errors.New("backup authentication failed: incorrect passphrase or damaged archive")
var ErrNotFound = errors.New("backup not found")

func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxArchiveSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxArchiveSize {
		clear(b)
		return nil, errors.New("backup exceeds 512 MiB limit")
	}
	return b, nil
}

func portableKey(passphrase string, salt []byte) ([]byte, error) {
	if len(passphrase) < 12 || len(passphrase) > 1024 {
		return nil, errors.New("portable backup passphrase must contain 12 to 1024 bytes")
	}
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 2, 32), nil
}

func encodePortable(snapshot, master []byte, passphrase string) ([]byte, error) {
	if len(master) != 32 {
		return nil, errors.New("invalid master key")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := portableKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	v, err := cryptoutil.New(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 32+len(snapshot))
	copy(plain, master)
	copy(plain[32:], snapshot)
	defer clear(plain)
	ciphertext, err := v.Encrypt(plain, portableMagic+":"+hex.EncodeToString(salt))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(portableMagic)+len(salt)+len(ciphertext))
	out = append(out, portableMagic...)
	out = append(out, salt...)
	out = append(out, ciphertext...)
	return out, nil
}

func decodePortable(archive []byte, passphrase string) (snapshot, master []byte, err error) {
	if len(archive) < len(portableMagic)+16+29+32 || !bytes.HasPrefix(archive, []byte(portableMagic)) {
		return nil, nil, ErrInvalidBackup
	}
	salt := archive[8:24]
	key, err := portableKey(passphrase, salt)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	v, err := cryptoutil.New(key)
	if err != nil {
		return nil, nil, err
	}
	plain, err := v.Decrypt(archive[24:], portableMagic+":"+hex.EncodeToString(salt))
	if err != nil {
		return nil, nil, ErrInvalidPassphrase
	}
	if len(plain) < 32+16 {
		clear(plain)
		return nil, nil, ErrInvalidBackup
	}
	// The caller clears both returned slices after the snapshot has been staged.
	return plain[32:], plain[:32], nil
}

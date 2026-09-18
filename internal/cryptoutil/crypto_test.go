package cryptoutil

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVaultAuthenticatesKeyPurposeAndCiphertext(t *testing.T) {
	v, err := New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := v.Encrypt([]byte("upstream-token"), "engine:one")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("upstream-token")) {
		t.Fatal("plaintext leaked")
	}
	second, err := v.Encrypt([]byte("upstream-token"), "engine:one")
	if err != nil || bytes.Equal(ct, second) {
		t.Fatal("encryption reused a nonce")
	}
	pt, err := v.Decrypt(ct, "engine:one")
	if err != nil || string(pt) != "upstream-token" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	other, _ := New(bytes.Repeat([]byte{2}, 32))
	if _, err = other.Decrypt(ct, "engine:one"); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err = v.Decrypt(ct, "engine:two"); err == nil {
		t.Fatal("wrong purpose accepted")
	}
	ct[len(ct)-1] ^= 1
	if _, err = v.Decrypt(ct, "engine:one"); err == nil {
		t.Fatal("tampering accepted")
	}
	if _, err = New(make([]byte, 16)); err == nil {
		t.Fatal("short master accepted")
	}
	for n := 0; n < 29; n++ {
		if _, err = v.Decrypt(make([]byte, n), "engine:one"); err == nil {
			t.Fatal("truncated ciphertext accepted")
		}
	}
}

func TestPasswordHashesAreSaltedAndBounded(t *testing.T) {
	first, err := HashPassword("a long enough administrator password")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("a long enough administrator password")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("password salts reused")
	}
	if !VerifyPassword(first, "a long enough administrator password") {
		t.Fatal("correct password refused")
	}
	if VerifyPassword(first, "wrong password") {
		t.Fatal("wrong password accepted")
	}
	for _, bad := range []string{"", "bad", strings.Replace(first, "m=65536", "m=4294967295", 1), strings.Replace(first, "t=3", "t=4294967295", 1), strings.Replace(first, "p=2", "p=0", 1), strings.Repeat("A", 4096)} {
		if VerifyPassword(bad, "a long enough administrator password") {
			t.Fatal("invalid hash accepted")
		}
	}
}

func TestIdentifiersAndLookupDigests(t *testing.T) {
	if got := HashSecret("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("digest %s", got)
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := RandomID()
		if len(id) != 32 || seen[id] {
			t.Fatalf("invalid ID %q", id)
		}
		seen[id] = true
	}
	k, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(k, "llmgw_") || len(k) < 45 {
		t.Fatalf("invalid API key %q", k)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(k, "llmgw_"))
	if err != nil || len(raw) != 32 {
		t.Fatal("API key must contain 32 bytes of entropy")
	}
}

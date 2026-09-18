//go:build darwin && cgo

package keychain

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryCaseAliasesUseOneKey(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "GatewayData")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "gatewaydata")
	if _, err := os.Stat(alias); os.IsNotExist(err) {
		t.Skip("test filesystem distinguishes directory case")
	} else if err != nil {
		t.Fatal(err)
	}
	store := &memoryBackend{}
	want, err := loadOrCreate(original, store, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := load(alias, store)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("case alias changed master-key scope: %v", err)
	}
}

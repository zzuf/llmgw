//go:build !darwin || !cgo

package keychain

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformFailsClosed(t *testing.T) {
	for _, loadKey := range []func(string) ([]byte, error){Load, LoadOrCreate} {
		key, err := loadKey(t.TempDir())
		if !errors.Is(err, ErrUnsupported) || key != nil {
			t.Fatalf("got key length %d, error %v; want unsupported", len(key), err)
		}
	}
}

//go:build !darwin || !cgo

package keychain

type nativeBackend struct{}

func canonicalExistingDirectory(path string) (string, error) { return path, nil }

func (nativeBackend) read(string) ([]byte, error) { return nil, ErrUnsupported }
func (nativeBackend) create(string, []byte) error { return ErrUnsupported }

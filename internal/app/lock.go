package app

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type Lock struct{ file *os.File }

func Acquire(dataDir string) (*Lock, error) {
	if e := os.MkdirAll(dataDir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(dataDir, "gateway.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("data directory is in use; stop the service before this operation: %w", e)
	}
	return &Lock{f}, nil
}
func (l *Lock) Close() error {
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}

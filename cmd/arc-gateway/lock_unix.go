//go:build arc && unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// afterFlock runs between taking the lock and checking its name. It does
// nothing outside tests, which use it to replace the file at that moment.
var afterFlock = func(path string) {}

// lockFile takes an exclusive, non-blocking flock on path and returns the open
// file that holds it. The lock lasts until that file is closed or the process
// exits (SPEC-ARC-GATE §6). holder names what the lock is for in errors.
func lockFile(path, holder string) (*os.File, error) {
	path = filepath.Clean(path)
	// #nosec G304 -- derived from the operator's -log or -state-dir path.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open lock %s: %w", arcpay.ErrUnavailable, path, err)
	}
	// #nosec G115 -- a file descriptor fits in an int.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: another arc-gateway is using %s (%s is held); stop it first", arcpay.ErrUnavailable, holder, path)
		}
		return nil, fmt.Errorf("%w: lock %s: %w", arcpay.ErrUnavailable, path, err)
	}
	afterFlock(path)
	// The lock binds the file that is open. If the name no longer refers to
	// it, a later gateway would lock a different file, so refuse.
	held, herr := f.Stat()
	named, nerr := os.Stat(path)
	if herr != nil || nerr != nil || !os.SameFile(held, named) {
		_ = f.Close()
		return nil, fmt.Errorf("%w: lock %s was replaced while it was being taken", arcpay.ErrUnavailable, path)
	}
	return f, nil
}

//go:build arc

package arcpay

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"
)

// LoadKey reads a secp256k1 key from a file and refuses a file anyone else can
// read or replace. The key never enters an environment variable and is never
// printed. Errors wrap ErrUnavailable (the file is missing or unreadable) or
// ErrViolation (the file is exposed).
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	// Lstat, not Stat: a symlink's target mode is not the thing an attacker
	// would have to change to substitute a key.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, unavailable(fmt.Errorf("no key file at %s: %w\n"+
			"  Create one with 64 hex characters (no 0x) and chmod 600:\n"+
			"    mkdir -p %s && (umask 077 && openssl rand -hex 32 > %s)", path, err, filepath.Dir(path), path))
	}
	if !info.Mode().IsRegular() {
		return nil, violation(fmt.Errorf("key path %s is not a regular file (mode %v)", path, info.Mode()))
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, violation(fmt.Errorf("key file %s is mode %04o, group- or world-readable.\n  chmod 600 %s", path, mode, path))
	}
	if dir, err := os.Stat(filepath.Dir(path)); err == nil && dir.Mode().Perm()&0o022 != 0 {
		return nil, violation(fmt.Errorf("directory %s is mode %04o, group- or world-WRITABLE, so the key file can be replaced.\n  chmod 700 %s", filepath.Dir(path), dir.Mode().Perm(), filepath.Dir(path)))
	}
	key, err := crypto.LoadECDSA(path)
	if err != nil {
		return nil, unavailable(fmt.Errorf("read key from %s: %w (want exactly 64 hex characters, no 0x prefix)", path, err))
	}
	return key, nil
}

//go:build arc

package arcpay

import (
	"crypto/ecdsa"
	"errors"
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
	resolved, err := ResolveKeyFile(path)
	if err != nil {
		return nil, err
	}
	key, err := crypto.LoadECDSA(resolved)
	if err != nil {
		return nil, unavailable(fmt.Errorf("read key from %s: %w (want exactly 64 hex characters, no 0x prefix)", resolved, err))
	}
	return key, nil
}

// CheckKeyFile reports whether ResolveKeyFile accepts path.
func CheckKeyFile(path string) error {
	_, err := ResolveKeyFile(path)
	return err
}

// ResolveKeyFile walks the directory of the cleaned path with
// ResolvePrivatePath and returns the key file's path under the resolved
// directory. It refuses a key file there that is missing, not a regular file,
// or readable by anyone but its owner. Every key this repository loads is read
// through the returned path, whatever the key type.
func ResolveKeyFile(flag string) (string, error) {
	clean := filepath.Clean(flag)
	dir, err := ResolvePrivatePath(filepath.Dir(clean))
	if errors.Is(err, os.ErrNotExist) {
		return "", unavailable(fmt.Errorf("no key directory for %s: %w\n"+
			"  Create it and a key with 64 hex characters (no 0x), mode 600:\n"+
			"    mkdir -p %s && chmod 700 %s && (umask 077 && openssl rand -hex 32 > %s)",
			clean, err, filepath.Dir(clean), filepath.Dir(clean), clean))
	}
	if err != nil {
		return "", fmt.Errorf("key %s: %w", clean, err)
	}
	path := filepath.Join(dir, filepath.Base(clean))
	// Lstat, not Stat: a symlink's target mode is not the thing an attacker
	// would have to change to substitute a key.
	info, err := os.Lstat(path)
	if err != nil {
		return "", unavailable(fmt.Errorf("no key file at %s: %w\n"+
			"  Create one with 64 hex characters (no 0x) and chmod 600:\n"+
			"    mkdir -p %s && (umask 077 && openssl rand -hex 32 > %s)", path, err, filepath.Dir(path), path))
	}
	if !info.Mode().IsRegular() {
		return "", violation(fmt.Errorf("key path %s is not a regular file (mode %v)", path, info.Mode()))
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", violation(fmt.Errorf("key file %s is mode %04o, group- or world-readable.\n  chmod 600 %s", path, mode, path))
	}
	return path, nil
}

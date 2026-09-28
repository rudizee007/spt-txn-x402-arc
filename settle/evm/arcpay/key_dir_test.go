//go:build arc && unix

package arcpay

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key file in a directory group or others can write is refused: the
// directory lets the key be replaced.
func TestKeyInWritableDirectoryIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "pay.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("11", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckKeyFile(key); err != nil {
		t.Fatalf("key in an owner-only directory: %v", err)
	}
	for _, mode := range []os.FileMode{0o770, 0o777} {
		if err := os.Chmod(dir, mode); err != nil { // #nosec G302 -- the case under test
			t.Fatal(err)
		}
		if err := CheckKeyFile(key); !errors.Is(err, ErrViolation) {
			t.Fatalf("key in a directory of mode %04o: %v", mode, err)
		}
	}
}

// The owner check on its own: /usr is owned by root and not group- or
// world-writable, so only the owner check can refuse it.
func TestOwnerOnlyDirRefusesAnotherOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: /usr is owned by this uid")
	}
	fi, err := os.Stat("/usr")
	if err != nil || fi.Mode().Perm()&0o022 != 0 {
		t.Skipf("/usr is not a root-owned, owner-only-writable directory here (%v)", err)
	}
	if err := CheckOwnerOnlyDir("/usr"); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "owned by uid 0") {
		t.Fatalf("root-owned directory: %v", err)
	}
	if err := CheckOwnerOnlyDir(t.TempDir()); err != nil {
		t.Fatalf("own temp directory: %v", err)
	}
}

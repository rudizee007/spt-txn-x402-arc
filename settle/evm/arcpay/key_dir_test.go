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

// The owner rule: this uid or root may own the directory; anyone else may
// not. The uid is swapped so the rule is exercised without root.
func TestOwnerOnlyDirOwners(t *testing.T) {
	if fi, err := os.Stat("/usr"); err == nil && fi.Mode().Perm()&0o022 == 0 {
		if err := CheckOwnerOnlyDir("/usr"); err != nil {
			t.Fatalf("root-owned directory refused: %v", err)
		}
	}
	own, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckOwnerOnlyDir(own); err != nil {
		t.Fatalf("own directory: %v", err)
	}
	real := effectiveUID
	defer func() { effectiveUID = real }()
	effectiveUID = func() uint32 { return real() + 1 }
	if err := CheckOwnerOnlyDir(own); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("directory owned by another uid: %v", err)
	}
	if err := CheckPrivatePath(own); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("path through directories owned by another uid: %v", err)
	}
}

// A directory that cannot be examined is unavailable, never accepted.
func TestMissingDirectoryIsUnavailable(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "absent")
	if err := CheckOwnerOnlyDir(missing); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CheckOwnerOnlyDir on a missing directory: %v", err)
	}
	if err := CheckPrivatePath(missing); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CheckPrivatePath on a missing directory: %v", err)
	}
}

// A directory above the checked one that another uid owns is refused, even
// when the checked directory itself is ours and owner-only.
func TestPrivatePathRefusesAForeignOwnedAncestor(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(base, "theirs", "ours")
	if err := os.MkdirAll(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivatePath(leaf); err != nil {
		t.Fatalf("all ours: %v", err)
	}
	real := ownerUID
	defer func() { ownerUID = real }()
	ownerUID = func(fi os.FileInfo) (uint32, bool) {
		if fi.Name() == "theirs" {
			return effectiveUID() + 4242, true
		}
		return real(fi)
	}
	if err := CheckPrivatePath(leaf); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "above") {
		t.Fatalf("ancestor owned by another uid: %v", err)
	}
}

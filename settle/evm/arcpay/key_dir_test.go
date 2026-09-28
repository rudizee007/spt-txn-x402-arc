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

// trustLinks makes symlinks with the given names report root as owner.
func trustLinks(t *testing.T, names ...string) {
	t.Helper()
	real := ownerUID
	t.Cleanup(func() { ownerUID = real })
	ownerUID = func(fi os.FileInfo) (uint32, bool) {
		for _, n := range names {
			if fi.Name() == n && fi.Mode()&os.ModeSymlink != 0 {
				return 0, true
			}
		}
		return real(fi)
	}
}

func resolvedTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mkdirs(t *testing.T, mode os.FileMode, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // #nosec G302 -- the case under test
		t.Fatal(err)
	}
	return path
}

// §6: a root-owned symlink is followed, with a relative or an absolute
// target, and the resolved path is returned; one not owned by root is refused.
func TestRootOwnedSymlinkIsFollowed(t *testing.T) {
	base := resolvedTemp(t)
	leaf := mkdirs(t, 0o700, filepath.Join(base, "real", "leaf"))
	if err := os.Symlink("real", filepath.Join(base, "rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "abs")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolvePrivatePath(filepath.Join(base, "rel", "leaf")); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "not owned by root") {
		t.Fatalf("symlink owned by this uid: %v", err)
	}
	trustLinks(t, "rel", "abs")
	for _, link := range []string{"rel", "abs"} {
		got, err := ResolvePrivatePath(filepath.Join(base, link, "leaf"))
		if err != nil || got != leaf {
			t.Fatalf("through %s: got %q, %v; want %q", link, got, err, leaf)
		}
	}
}

// §6: the target of a followed symlink is walked in full.
func TestFollowedSymlinkTargetIsWalked(t *testing.T) {
	base := resolvedTemp(t)
	wide := mkdirs(t, 0o777, filepath.Join(base, "wide"))
	mkdirs(t, 0o700, filepath.Join(wide, "leaf"))
	if err := os.Symlink(wide, filepath.Join(base, "tw")); err != nil {
		t.Fatal(err)
	}
	trustLinks(t, "tw")
	if _, err := ResolvePrivatePath(filepath.Join(base, "tw", "leaf")); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "not sticky") {
		t.Fatalf("root-owned link into a writable directory: %v", err)
	}
}

// §6: the last directory may itself be a root-owned symlink; it is judged
// where it resolves.
func TestLastDirectoryMayBeARootOwnedSymlink(t *testing.T) {
	base := resolvedTemp(t)
	leaf := mkdirs(t, 0o700, filepath.Join(base, "real", "leaf"))
	if err := os.Symlink(leaf, filepath.Join(base, "leaflink")); err != nil {
		t.Fatal(err)
	}
	trustLinks(t, "leaflink")
	got, err := ResolvePrivatePath(filepath.Join(base, "leaflink"))
	if err != nil || got != leaf {
		t.Fatalf("got %q, %v; want %q", got, err, leaf)
	}
}

// §6: a symlink loop is refused after a bounded number of links.
func TestSymlinkLoopIsRefused(t *testing.T) {
	base := resolvedTemp(t)
	if err := os.Symlink("b", filepath.Join(base, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(base, "b")); err != nil {
		t.Fatal(err)
	}
	trustLinks(t, "a", "b")
	if _, err := ResolvePrivatePath(filepath.Join(base, "a", "x")); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "symlinks on the path") {
		t.Fatalf("symlink loop: %v", err)
	}
}

// ResolveParentPath judges the last directory by the rule for a directory
// above: a sticky, writable directory is accepted there, and refused by
// ResolvePrivatePath.
func TestParentRuleAcceptsASticky(t *testing.T) {
	sticky := mkdirs(t, 0o777|os.ModeSticky, filepath.Join(resolvedTemp(t), "sticky"))
	if _, err := ResolveParentPath(sticky); err != nil {
		t.Fatalf("sticky directory as a parent: %v", err)
	}
	if _, err := ResolvePrivatePath(sticky); !errors.Is(err, ErrViolation) {
		t.Fatalf("sticky directory as the last directory: %v", err)
	}
}

// A real system symlink owned by root, such as /var or /tmp on macOS, is
// followed.
func TestSystemSymlinkIsFollowed(t *testing.T) {
	raw := t.TempDir()
	want, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	if want == raw {
		t.Skip("the temp directory has no symlink on this host")
	}
	got, err := ResolvePrivatePath(raw)
	if err != nil || got != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
}

// §6: the directory holding a key file is walked like the gateway's own.
func TestKeyDirectoryIsWalked(t *testing.T) {
	shared := mkdirs(t, 0o770, filepath.Join(resolvedTemp(t), "shared"))
	keys := mkdirs(t, 0o700, filepath.Join(shared, "keys"))
	key := filepath.Join(keys, "pay.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("11", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckKeyFile(key); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "not sticky") {
		t.Fatalf("key below a group-writable directory: %v", err)
	}
}

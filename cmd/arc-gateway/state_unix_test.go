//go:build arc && unix

package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

func newPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	return pub
}

// §6: a log directory group or others can write is refused before anything
// is created or read in it.
func TestLogDirMustBeOwnerOnly(t *testing.T) {
	for _, mode := range []os.FileMode{0o775, 0o777, 0o720, 0o707, 0o702} {
		dir := filepath.Join(tempDir(t), "logs")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil { // #nosec G302 -- the case under test
			t.Fatal(err)
		}
		path := filepath.Join(dir, "decisions.json")
		_, err := openLogState(path, testState(t), newPub(t), [32]byte{1})
		if !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "only its owner can write") {
			t.Fatalf("log directory mode %04o: %v", mode, err)
		}
		for _, f := range []string{path, path + ".lock"} {
			if _, statErr := os.Stat(f); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("log directory mode %04o: %s was created", mode, f)
			}
		}
	}
}

// §6: a state or log directory owned by another uid is refused, even when its
// mode is 0700. Needs permission to chown, which normally means root.
func TestDirOwnedByAnotherUserIsRefused(t *testing.T) {
	for _, which := range []string{"state", "log"} {
		dir := filepath.Join(tempDir(t), which)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, os.Geteuid()+1, -1); err != nil {
			t.Skipf("cannot chown a directory to another uid in this environment (%v); the owner check is not exercised here, the mode checks are", err)
		}
		logPath, stateDir := filepath.Join(tempDir(t), "decisions.json"), dir
		if which == "log" {
			logPath, stateDir = filepath.Join(dir, "decisions.json"), testState(t)
		}
		_, err := openLogState(logPath, stateDir, newPub(t), [32]byte{1})
		if !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "owned by uid") {
			t.Fatalf("%s directory owned by another uid: %v", which, err)
		}
	}
}

// §6: -log must name the real file. A symlink is refused, and no lock is
// taken beside the link or beside its target.
func TestSymlinkedLogIsRefused(t *testing.T) {
	dir := tempDir(t)
	target := filepath.Join(dir, "real.json")
	l, _ := logWith(t, 1, 0)
	if err := l.Save(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := openLogState(link, testState(t), l.PublicKey(), [32]byte{1})
	if !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "symlink") {
		t.Fatalf("symlinked -log: %v", err)
	}
	for _, f := range []string{target + ".lock", link + ".lock"} {
		if _, statErr := os.Stat(f); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("a lock was created at %s", f)
		}
	}
}

// §6: a -log whose directory is a symlink is refused, whether or not the log
// exists yet.
func TestLogInSymlinkedDirectoryIsRefused(t *testing.T) {
	real := filepath.Join(tempDir(t), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(tempDir(t), "linkdir")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(linkDir, "decisions.json")
	_, err := openLogState(path, testState(t), newPub(t), [32]byte{1})
	if !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "symlink") {
		t.Fatalf("new log in a symlinked directory: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(real, "decisions.json.lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a lock was created in the symlink's target directory")
	}
	l, _ := logWith(t, 1, 0)
	if err := l.Save(filepath.Join(real, "decisions.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogState(path, testState(t), l.PublicKey(), [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("existing log in a symlinked directory: %v", err)
	}
}

// foreignDir finds an existing directory owned by a uid that is neither this
// process's nor root's, not writable by group or others, whose parent path is
// private. It skips the test if the host has none.
func foreignDir(t *testing.T) string {
	t.Helper()
	var candidates []string
	for _, glob := range []string{"/private/var/*", "/var/*", "/usr/local/*", "/opt/*", "/srv/*"} {
		m, _ := filepath.Glob(glob)
		candidates = append(candidates, m...)
	}
	for _, c := range candidates {
		fi, err := os.Lstat(c)
		if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid == 0 || int(st.Uid) == os.Geteuid() {
			continue
		}
		if arcpay.CheckPrivatePath(filepath.Dir(c)) != nil {
			continue
		}
		return c
	}
	t.Skip("no directory owned by another non-root uid on this host")
	return ""
}

// §6: a log or state directory owned by another non-root uid is refused, at
// both call sites, without needing chown.
func TestLogAndStateDirOwnedByAnotherUidAreRefused(t *testing.T) {
	dir := foreignDir(t)
	_, err := openLogState(filepath.Join(dir, "decisions.json"), testState(t), newPub(t), [32]byte{1})
	if !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "owned by uid") {
		t.Fatalf("log directory %s owned by another uid: %v", dir, err)
	}
	path, pub := stateDir(t)
	if _, err := openLogState(path, dir, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "owned by uid") {
		t.Fatalf("state directory %s owned by another uid: %v", dir, err)
	}
}

func mkdirMode(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // #nosec G302 -- the case under test
		t.Fatal(err)
	}
	return path
}

// §6: a directory above the log or state directory that group or others can
// write, without the sticky bit, is refused; with the sticky bit it is
// accepted.
func TestWritableAncestorNeedsTheStickyBit(t *testing.T) {
	base := tempDir(t)
	shared := mkdirMode(t, filepath.Join(base, "shared"), 0o777)
	logs := mkdirMode(t, filepath.Join(shared, "logs"), 0o700)
	state := filepath.Join(shared, "state")
	if _, err := openLogState(filepath.Join(logs, "decisions.json"), testState(t), newPub(t), [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "not sticky") {
		t.Fatalf("log under a writable, non-sticky directory: %v", err)
	}
	path, pub := stateDir(t)
	if _, err := openLogState(path, state, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "not sticky") {
		t.Fatalf("state directory under a writable, non-sticky directory: %v", err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil { // #nosec G302 -- the case under test
		t.Fatal(err)
	}
	st, err := openLogState(filepath.Join(logs, "decisions.json"), state, newPub(t), [32]byte{1})
	if err != nil {
		t.Fatalf("log and state under a sticky directory: %v", err)
	}
	_ = st.close()
}

// §6: the sticky bit is an exception only above; the log and state
// directories themselves must not be writable by group or others at all.
func TestStickyLeafDirIsRefused(t *testing.T) {
	base := tempDir(t)
	logs := mkdirMode(t, filepath.Join(base, "logs"), 0o777|os.ModeSticky)
	if _, err := openLogState(filepath.Join(logs, "decisions.json"), testState(t), newPub(t), [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("sticky, writable log directory: %v", err)
	}
	state := mkdirMode(t, filepath.Join(base, "state"), 0o777|os.ModeSticky)
	path, pub := stateDir(t)
	if _, err := openLogState(path, state, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("sticky, writable state directory: %v", err)
	}
}

// §6: a symlink anywhere above the log or state directory is refused.
func TestSymlinkedAncestorIsRefused(t *testing.T) {
	base := tempDir(t)
	mkdirMode(t, filepath.Join(base, "real", "sub"), 0o700)
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "real"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogState(filepath.Join(link, "sub", "decisions.json"), testState(t), newPub(t), [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "symlink") {
		t.Fatalf("log below a symlinked directory: %v", err)
	}
	path, pub := stateDir(t)
	if _, err := openLogState(path, filepath.Join(link, "state"), pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "symlink") {
		t.Fatalf("state directory below a symlinked directory: %v", err)
	}
}

// §6: a ".." after a symlink is removed lexically before anything is opened,
// so every file lands in the directory that was checked.
func TestPathsAreCleanedBeforeUse(t *testing.T) {
	base := tempDir(t)
	a := mkdirMode(t, filepath.Join(base, "a"), 0o700)
	wide := mkdirMode(t, filepath.Join(base, "wide", "sub"), 0o700)
	if err := os.Symlink(wide, filepath.Join(a, "b")); err != nil {
		t.Fatal(err)
	}
	// Concatenated, not filepath.Join, which would clean the ".." away.
	raw := a + string(filepath.Separator) + "b" + string(filepath.Separator) + ".." + string(filepath.Separator) + "decisions.json"
	st, err := openLogState(raw, testState(t), newPub(t), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	st.used = 1
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	_ = st.close()
	entries, _ := os.ReadDir(filepath.Join(base, "wide"))
	for _, e := range entries {
		if e.Name() != "sub" {
			t.Fatalf("a file landed beside the symlink's target: %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(a, "decisions.json")); err != nil {
		t.Fatalf("log not in the checked directory: %v", err)
	}
}

// §6: a -log that cannot be examined is unavailable, not accepted.
func TestUnreadableLogPathIsUnavailable(t *testing.T) {
	logs := mkdirMode(t, filepath.Join(tempDir(t), "logs"), 0o600) // no search permission
	defer func() { _ = os.Chmod(logs, 0o700) }()
	if _, err := openLogState(filepath.Join(logs, "decisions.json"), testState(t), newPub(t), [32]byte{1}); !errors.Is(err, arcpay.ErrUnavailable) {
		t.Fatalf("log in a directory without search permission: %v", err)
	}
}

// §3, §6: -state-dir and -log have no default. An empty one is refused and
// nothing is created in the working directory.
func TestEmptyStateOrLogPathIsRefused(t *testing.T) {
	cwd := tempDir(t)
	t.Chdir(cwd)
	path, pub := stateDir(t)
	for _, empty := range []string{"", "  ", "\t"} {
		if _, err := openLogState(path, empty, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrUnavailable) || !strings.Contains(errText(err), "/var/lib/spt-txn-arc/state") {
			t.Fatalf("empty -state-dir %q: %v", empty, err)
		}
	}
	for _, empty := range []string{"", "  ", "\t"} {
		if _, err := openLogState(empty, testState(t), pub, [32]byte{1}); !errors.Is(err, arcpay.ErrUnavailable) {
			t.Fatalf("empty -log %q: %v", empty, err)
		}
	}
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Fatalf("files created in the working directory: %v", entries)
	}
}

// §6: a directory above that group can write, without the sticky bit, is
// refused, as one that others can write is.
func TestGroupWritableAncestorIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o775} {
		shared := mkdirMode(t, filepath.Join(tempDir(t), "shared"), mode)
		logs := mkdirMode(t, filepath.Join(shared, "logs"), 0o700)
		if _, err := openLogState(filepath.Join(logs, "decisions.json"), testState(t), newPub(t), [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "not sticky") {
			t.Fatalf("log under a directory of mode %04o: %v", mode, err)
		}
		path, pub := stateDir(t)
		if _, err := openLogState(path, filepath.Join(shared, "state"), pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "not sticky") {
			t.Fatalf("state directory under a directory of mode %04o: %v", mode, err)
		}
	}
}

// §6: -log and -state-dir must be absolute; a relative one is refused before
// anything is created, and so is -state-dir set to the root directory.
func TestRelativeOrRootPathsAreRefused(t *testing.T) {
	cwd := tempDir(t)
	t.Chdir(cwd)
	abs, pub := stateDir(t)
	for _, c := range []struct{ log, state string }{
		{"decisions.json", testState(t)},
		{filepath.Join("logs", "decisions.json"), testState(t)},
		{filepath.Join("..", "decisions.json"), testState(t)},
		{"./decisions.json", testState(t)},
		{abs, "state"},
		{abs, "../state"},
	} {
		if _, err := openLogState(c.log, c.state, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "must be absolute paths") {
			t.Fatalf("relative -log %q / -state-dir %q: %v", c.log, c.state, err)
		}
	}
	for _, root := range []string{"/", "//", "/./"} {
		if _, err := openLogState(abs, root, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "root directory") {
			t.Fatalf("-state-dir %q: %v", root, err)
		}
	}
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Fatalf("files created in the working directory: %v", entries)
	}
}

// §6: the state directory is created only inside a parent that passed the
// walk; a missing or writable parent refuses and nothing is created.
func TestStateDirIsCreatedOnlyInAVerifiedParent(t *testing.T) {
	base := tempDir(t)
	path, pub := stateDir(t)
	if _, err := openLogState(path, filepath.Join(base, "missing", "state"), pub, [32]byte{1}); !errors.Is(err, arcpay.ErrUnavailable) {
		t.Fatalf("missing parent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the missing parent was created")
	}
	shared := mkdirMode(t, filepath.Join(base, "shared"), 0o777)
	if _, err := openLogState(path, filepath.Join(shared, "state"), pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("writable parent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(shared, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the state directory was created in a parent that failed the walk")
	}
}

// §6: a path through a root-owned system symlink (on macOS the temp directory
// is under /var) is followed, and the files are opened through the resolved
// path.
func TestGatewayFollowsSystemSymlinks(t *testing.T) {
	raw := t.TempDir()
	real, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	if real == raw {
		t.Skip("the temp directory has no symlink on this host")
	}
	st, err := openLogState(filepath.Join(raw, "decisions.json"), filepath.Join(raw, "state"), newPub(t), [32]byte{1})
	if err != nil {
		t.Fatalf("path through a root-owned symlink: %v", err)
	}
	defer func() { _ = st.close() }()
	if st.path != filepath.Join(real, "decisions.json") || st.stateDir != filepath.Join(real, "state") {
		t.Fatalf("not opened through the resolved path: %q, %q", st.path, st.stateDir)
	}
}

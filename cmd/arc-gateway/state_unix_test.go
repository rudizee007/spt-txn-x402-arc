//go:build arc && unix

package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	for _, mode := range []os.FileMode{0o775, 0o777, 0o720} {
		dir := filepath.Join(t.TempDir(), "logs")
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
		dir := filepath.Join(t.TempDir(), which)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, os.Geteuid()+1, -1); err != nil {
			t.Skipf("cannot chown a directory to another uid in this environment (%v); the owner check is not exercised here, the mode checks are", err)
		}
		logPath, stateDir := filepath.Join(t.TempDir(), "decisions.json"), dir
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
	dir := t.TempDir()
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
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(t.TempDir(), "linkdir")
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

// The owner check without chown: /usr is owned by root and mode 0755, so it
// passes the mode check and only the owner check can refuse it. MkdirAll on
// the existing directory succeeds, and the owner check still refuses.
func TestExistingRootOwnedStateDirIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: /usr is owned by this uid")
	}
	fi, err := os.Stat("/usr")
	if err != nil || fi.Mode().Perm()&0o022 != 0 {
		t.Skipf("/usr is not a root-owned, owner-only-writable directory here (%v)", err)
	}
	path := filepath.Join(t.TempDir(), "decisions.json")
	_, err = openLogState(path, "/usr", newPub(t), [32]byte{1})
	if !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "owned by uid 0") {
		t.Fatalf("root-owned state directory: %v", err)
	}
}

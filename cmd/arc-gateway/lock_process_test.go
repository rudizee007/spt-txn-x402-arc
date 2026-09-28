//go:build arc && unix

package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// Two separate processes on one log. The child
// holds the lock until its stdin closes; while it does, this process cannot
// open the log, and once it exits, it can.
func TestLockHeldByAnotherProcess(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldLogLock$") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), "ARC_GATEWAY_HOLD_LOCK="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		t.Fatalf("child did not take the lock: %q, %v", line, err)
	}
	if _, err := openLogState(path, sd, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrUnavailable) {
		t.Fatalf("opened a log another process holds: %v", err)
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v", err)
	}
	st, err := openLogState(path, sd, pub, [32]byte{1})
	if err != nil {
		t.Fatalf("after the other process exited: %v", err)
	}
	_ = st.close()
}

// TestHelperHoldLogLock is the child process of TestLockHeldByAnotherProcess.
func TestHelperHoldLogLock(t *testing.T) {
	path := os.Getenv("ARC_GATEWAY_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process only")
	}
	f, err := lockFile(filepath.Clean(path)+".lock", "log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = os.Stdout.WriteString("locked\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// A lock file replaced after it was locked is refused: the name no longer
// refers to the locked file.
func TestLockFileReplacedWhileTakenIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	afterFlock = func(p string) {
		_ = os.Remove(p)
		_ = os.WriteFile(p, nil, 0o600)
	}
	defer func() { afterFlock = func(string) {} }()
	if _, err := lockFile(path, "test"); !errors.Is(err, arcpay.ErrUnavailable) || !strings.Contains(errText(err), "replaced") {
		t.Fatalf("replaced lock file: %v", err)
	}
}

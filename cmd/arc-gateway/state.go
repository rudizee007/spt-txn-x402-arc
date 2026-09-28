//go:build arc

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// stateDirRequired is the refusal for a missing or empty -state-dir.
const stateDirRequired = "-state-dir is required and has no default; on Linux use /var/lib/spt-txn-arc/state (RUNBOOK-ARC.md, install layout)"

// checkPathFlags refuses a -log or -state-dir that is empty or whitespace
// (before cleaning, which would turn it into "."), that is not absolute, or a
// -state-dir that is the root directory (SPEC-ARC-GATE §6). main calls it while
// validating flags, and openLogState calls it again.
func checkPathFlags(logPath, stateDir string) error {
	if strings.TrimSpace(logPath) == "" {
		return fmt.Errorf("%w: -log is required and has no default", arcpay.ErrUnavailable)
	}
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("%w: %s", arcpay.ErrUnavailable, stateDirRequired)
	}
	if !filepath.IsAbs(logPath) || !filepath.IsAbs(stateDir) {
		return fmt.Errorf("%w: -log and -state-dir must be absolute paths", arcpay.ErrViolation)
	}
	if filepath.Clean(stateDir) == string(filepath.Separator) {
		return fmt.Errorf("%w: -state-dir must not be the root directory", arcpay.ErrViolation)
	}
	return nil
}

// logState is what the gateway holds while it runs (SPEC-ARC-GATE §3, §6): a
// lock on its log, a lock on its capability, the log, the payment count for the
// capability, and the size of the last head recorded as on chain.
type logState struct {
	path       string // the -log path
	countPath  string // the capability's count, in the state directory
	besidePath string // the capability's count, beside the log
	digest     [32]byte
	lock       *os.File
	capLock    *os.File
	log        *translog.Log
	used       int
	saved      int // log size at the last successful save
	published  int // entries covered by the last recorded checkpoint; 0 if none
}

// openLogState takes both locks first and reads nothing before it holds them.
// The log lock is keyed by the log's path; the capability lock and count are
// keyed by the capability's digest in one state directory, so every gateway on
// this capability, whatever its log path, meets the same lock and count.
func openLogState(logPath, stateDir string, pub ed25519.PublicKey, capDigest [32]byte) (*logState, error) {
	if err := checkPathFlags(logPath, stateDir); err != nil {
		return nil, err
	}
	// Every file is opened through the cleaned paths that were checked.
	logPath, stateDir = filepath.Clean(logPath), filepath.Clean(stateDir)
	if err := checkLogPath(logPath); err != nil {
		return nil, err
	}
	lock, err := lockFile(logPath+".lock", "log "+logPath)
	if err != nil {
		return nil, err
	}
	if err := checkStateDir(stateDir); err != nil {
		_ = lock.Close()
		return nil, err
	}
	id := hex.EncodeToString(capDigest[:])
	capLock, err := lockFile(filepath.Join(stateDir, id+".lock"), "capability "+id[:16])
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	fail := func(err error) (*logState, error) {
		_ = errors.Join(capLock.Close(), lock.Close())
		return nil, err
	}
	l, err := openLog(logPath, pub)
	if err != nil {
		return fail(err)
	}
	countPath := filepath.Join(stateDir, id+".count")
	used, err := loadCount(countPath, capDigest)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}
	// The count is also kept beside the log, per capability, so a gateway on
	// the same log with a different -state-dir still sees it. An
	// unkeyed <log>.count from an earlier version is read and never written.
	// The highest is used; the two keyed copies are written.
	besidePath := logPath + "." + id + ".count"
	beside, err := loadCount(besidePath, capDigest)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}
	legacy, err := loadCount(logPath+".count", capDigest)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}
	used = max(used, beside, legacy)
	published, err := loadCheckpointHead(logPath+".checkpoint", l)
	if err != nil {
		return fail(err)
	}
	st := &logState{path: logPath, countPath: countPath, besidePath: besidePath, digest: capDigest, lock: lock, capLock: capLock,
		log: l, used: used, saved: l.Len(), published: published}
	// Writing both counts now finds, at startup, a location that cannot be
	// written or synced, rather than at the first decision.
	if err := st.saveCounts(); err != nil {
		return fail(fmt.Errorf("%w: write payment count: %w", arcpay.ErrUnavailable, err))
	}
	return st, nil
}

// save persists the count and the log after a decision (SPEC-ARC-GATE §6),
// first confirming that both locks are still the files their names refer to.
// The counts are written before the log, so an interruption leaves the count
// at or above the ALLOWs in the log. If anything fails, the caller settles
// nothing.
func (s *logState) save() error {
	if err := errors.Join(stillHeld(s.lock), stillHeld(s.capLock)); err != nil {
		return err
	}
	if err := s.saveCounts(); err != nil {
		return err
	}
	if err := s.log.Save(s.path); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	s.saved = s.log.Len()
	return nil
}

// saveCounts writes the count to the state directory and beside the log.
func (s *logState) saveCounts() error {
	return errors.Join(saveCount(s.countPath, s.digest, s.used), saveCount(s.besidePath, s.digest, s.used))
}

// stillHeld reports an error if the lock file's name no longer refers to the
// open file that holds the lock.
func stillHeld(f *os.File) error {
	held, herr := f.Stat()
	named, nerr := os.Stat(f.Name())
	if herr != nil || nerr != nil || !os.SameFile(held, named) {
		return fmt.Errorf("%w: lock %s is no longer in place", arcpay.ErrUnavailable, f.Name())
	}
	return nil
}

// checkLogPath refuses a -log whose directory, or any directory above it, is
// not private to this account (arcpay.CheckPrivatePath), and a -log that is
// itself a symlink (SPEC-ARC-GATE §6). The lock, the count copy and the
// checkpoint record live beside the log, so this one check covers them.
// Symlinks are refused, not resolved: the operator names the real file.
func checkLogPath(logPath string) error {
	p := filepath.Clean(logPath)
	if err := arcpay.CheckPrivatePath(filepath.Dir(p)); err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%w: -log %s is a symlink; name the real file", arcpay.ErrViolation, p)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: log %s: %w", arcpay.ErrUnavailable, p, err)
	}
	return nil
}

// checkStateDir creates the state directory if needed and refuses it unless it
// and every directory above it are private to this account
// (arcpay.CheckPrivatePath): whoever can replace a count file can reset it.
func checkStateDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("%w: no state directory", arcpay.ErrUnavailable)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: create state directory %s: %w", arcpay.ErrUnavailable, dir, err)
	}
	return arcpay.CheckPrivatePath(dir)
}

// checkpointer builds the log's checkpointer from this state, so it starts
// from the recorded head and records each new one beside this log.
func (s *logState) checkpointer(net evm.ArcNetwork, c *ethclient.Client, k *ecdsa.PrivateKey, every int, diag io.Writer) *checkpointer {
	return newCheckpointer(net, c, k, s.log, every, func() int { return s.saved }, s.published, s.path+".checkpoint", diag)
}

// close releases both locks. Exiting releases them too.
func (s *logState) close() error { return errors.Join(s.capLock.Close(), s.lock.Close()) }

// checkpointHead records the last log head published on chain.
type checkpointHead struct {
	N    int    `json:"n"`
	Root string `json:"root"`
	Tx   string `json:"tx"`
}

// loadCheckpointHead returns the size of the recorded head, or 0 if there is no
// record. It refuses a record the log on disk cannot account for: more entries
// than the log holds, or a root the log's first n entries do not hash to.
func loadCheckpointHead(path string, l *translog.Log) (int, error) {
	// #nosec G304 -- derived from the operator's -log path.
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: read %s: %w", arcpay.ErrUnavailable, path, err)
	}
	var h checkpointHead
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil || h.N < 1 {
		return 0, fmt.Errorf("%w: checkpoint record %s is malformed", arcpay.ErrViolation, path)
	}
	want, err := hex.DecodeString(h.Root)
	if err != nil || len(want) != 32 {
		return 0, fmt.Errorf("%w: checkpoint record %s is malformed", arcpay.ErrViolation, path)
	}
	if h.N > l.Len() {
		return 0, fmt.Errorf("%w: %s records a checkpoint of %d entries but the log holds %d; the log on disk does not match its checkpoint record",
			arcpay.ErrViolation, path, h.N, l.Len())
	}
	got := rootAt(l, h.N)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return 0, fmt.Errorf("%w: the log's first %d entries hash to %x, not the recorded checkpoint root %x; the log on disk does not match its checkpoint record",
			arcpay.ErrViolation, h.N, got, want)
	}
	return h.N, nil
}

// rootAt is the log's published root over its first n entries.
func rootAt(l *translog.Log, n int) [32]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		r, _ := l.At(i) // i < n <= l.Len()
		leaves[i] = r.CanonicalBytes()
	}
	return translog.MerkleRoot(leaves)
}

// saveCheckpointHead records a published head atomically.
func saveCheckpointHead(path string, n int, root [32]byte, tx common.Hash) error {
	b, err := json.Marshal(checkpointHead{N: n, Root: hex.EncodeToString(root[:]), Tx: tx.Hex()})
	if err != nil {
		return err
	}
	return writeAtomic(path, ".arc-gateway-checkpoint-*.tmp", b)
}

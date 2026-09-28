//go:build arc

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay/arcpaytest"
)

func stateDir(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	return filepath.Join(t.TempDir(), "decisions.json"), pub
}

// testState is one state directory shared by every gateway in a test.
func testState(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state")
}

// §6: one gateway per log. A second one refuses while the first holds the
// log, and starts once the first has gone.
func TestSecondGatewayOnOneLogRefusesToStart(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	first, err := openLogState(path, sd, pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openLogState(path, sd, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrUnavailable) || !strings.Contains(err.Error(), "another arc-gateway") {
		t.Fatalf("second gateway on one log: %v", err)
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	second, err := openLogState(path, sd, pub, [32]byte{1})
	if err != nil {
		t.Fatalf("after the first gateway exited: %v", err)
	}
	_ = second.close()
}

// §6: nothing is read before the lock is held. With the lock held elsewhere,
// a malformed count file is never reached: the refusal is the lock's.
func TestNothingIsReadBeforeTheLock(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	held, err := lockFile(path+".lock", "log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := os.WriteFile(path+".count", []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = openLogState(path, sd, pub, [32]byte{1})
	if !strings.Contains(errText(err), "another arc-gateway") {
		t.Fatalf("expected the lock refusal before any read, got %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the log was created before the lock was held")
	}
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// The count a second start sees is the count the first one saved.
func TestStateResumesTheSavedCount(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	if err := checkStateDir(sd); err != nil {
		t.Fatal(err)
	}
	if err := saveCount(filepath.Join(sd, hex.EncodeToString(bytes32(7))+".count"), [32]byte{7}, 1); err != nil {
		t.Fatal(err)
	}
	st, err := openLogState(path, sd, pub, [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	if st.used != 1 {
		t.Fatalf("used = %d, want 1", st.used)
	}
}

func logWith(t *testing.T, n int, salt byte) (*translog.Log, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	l := translog.NewLog(pub)
	for i := 0; i < n; i++ {
		if _, err := l.Append(priv, translog.DenyViolation, [32]byte{byte(i + 1), salt}, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	return l, priv
}

// §6: startup refuses a checkpoint record the log on disk cannot account for,
// and accepts one that covers a prefix of it.
func TestCheckpointRecordMustMatchTheLog(t *testing.T) {
	l, priv := logWith(t, 3, 0)
	root, _ := l.Head()
	path := filepath.Join(t.TempDir(), "log.checkpoint")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if n, err := loadCheckpointHead(path, l); n != 0 || err != nil {
		t.Fatalf("no record: %d, %v", n, err)
	}
	if err := saveCheckpointHead(path, 3, root, common.Hash{1}); err != nil {
		t.Fatal(err)
	}
	if n, err := loadCheckpointHead(path, l); n != 3 || err != nil {
		t.Fatalf("matching record: %d, %v", n, err)
	}
	// A longer log still accounts for a head over its first three entries.
	if _, err := l.Append(priv, translog.Allow, [32]byte{9}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if n, err := loadCheckpointHead(path, l); n != 3 || err != nil {
		t.Fatalf("record over a prefix: %d, %v", n, err)
	}

	short, _ := logWith(t, 2, 0)
	if _, err := loadCheckpointHead(path, short); !errors.Is(err, arcpay.ErrViolation) || !strings.Contains(errText(err), "the log holds 2") {
		t.Fatalf("record beyond the log's length: %v", err)
	}
	other, _ := logWith(t, 3, 1) // different records, same length
	if _, err := loadCheckpointHead(path, other); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("record whose root the log does not hash to: %v", err)
	}
	// Each malformed record is otherwise valid, so only the check it names
	// can refuse it.
	good := hex.EncodeToString(root[:])
	empty := translog.MerkleRoot(nil)
	for _, bad := range []string{
		"not json",
		`{"n":0,"root":"` + hex.EncodeToString(empty[:]) + `","tx":""}`,
		`{"n":3,"root":"abcd","tx":""}`,
		`{"n":3,"root":"` + good + `","tx":"","extra":1}`,
	} {
		write(bad)
		if _, err := loadCheckpointHead(path, l); !errors.Is(err, arcpay.ErrViolation) {
			t.Fatalf("malformed record %q: %v", bad, err)
		}
	}
}

// §6: a head recorded by one run is not published again by the next.
func TestRecordedHeadIsNotPublishedAgain(t *testing.T) {
	fake, cp, l, _ := checkpointFixture(t)
	cp.publishNow()
	if len(fake.Broadcasts()) != 1 {
		t.Fatalf("first run published %d checkpoints, want 1", len(fake.Broadcasts()))
	}
	published, err := loadCheckpointHead(cp.headPath, l)
	if err != nil || published != 3 {
		t.Fatalf("recorded head: %d, %v", published, err)
	}
	next := newCheckpointer(cp.net, cp.client, cp.key, l, 1, cp.savedSize, published, cp.headPath, &bytes.Buffer{})
	next.publishNow()
	if len(fake.Broadcasts()) != 1 {
		t.Fatalf("the next run published the recorded head again: %d broadcasts", len(fake.Broadcasts()))
	}
}

// A record that cannot be saved is reported, and the checkpoint still counts
// as published for this run.
func TestUnrecordedCheckpointIsReported(t *testing.T) {
	fake, cp, _, _ := checkpointFixture(t)
	var diag bytes.Buffer
	cp.diag = &diag
	cp.headPath = filepath.Join(t.TempDir(), "missing-dir", "log.checkpoint")
	cp.publishNow()
	if len(fake.Broadcasts()) != 1 || !strings.Contains(diag.String(), "was not recorded") {
		t.Fatalf("broadcasts %d, diag %q", len(fake.Broadcasts()), diag.String())
	}
	cp.publishNow()
	if len(fake.Broadcasts()) != 1 {
		t.Fatalf("the same head was checkpointed again in one run")
	}
}

// The checkpointer main builds from the state starts from the recorded head
// and records beside this log.
func TestStateCheckpointerStartsFromTheRecordedHead(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	st, err := openLogState(path, sd, pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	st.published = 4
	cp := st.checkpointer(evm.ArcTestnet(), nil, nil, 1, io.Discard)
	if cp.published != 4 || cp.headPath != path+".checkpoint" {
		t.Fatalf("checkpointer from state: published %d, headPath %q", cp.published, cp.headPath)
	}
}

// The state carries the log on disk, not a fresh one.
func TestStateLoadsTheSavedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	l, _ := logWith(t, 2, 0)
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := openLogState(path, testState(t), l.PublicKey(), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	if st.log.Len() != 2 {
		t.Fatalf("state log has %d entries, want 2", st.log.Len())
	}
}

func bytes32(b byte) []byte { d := [32]byte{b}; return d[:] }

// §3, §6: the capability, not the log path, owns the count. A second gateway
// on the same capability with a different log refuses to start; a gateway on
// a different capability starts beside it.
func TestSameCapabilityDifferentLogRefusesToStart(t *testing.T) {
	sd := testState(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	a, err := openLogState(filepath.Join(t.TempDir(), "a.json"), sd, pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.close() }()
	if _, err := openLogState(filepath.Join(t.TempDir(), "b.json"), sd, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrUnavailable) || !strings.Contains(errText(err), "capability") {
		t.Fatalf("second gateway on one capability, other log: %v", err)
	}
	c, err := openLogState(filepath.Join(t.TempDir(), "c.json"), sd, pub, [32]byte{2})
	if err != nil {
		t.Fatalf("gateway on another capability: %v", err)
	}
	_ = c.close()
}

// The count a gateway saves is the count the next one sees, whatever log path
// either uses.
func TestCountFollowsTheCapabilityAcrossLogs(t *testing.T) {
	sd := testState(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	a, err := openLogState(filepath.Join(t.TempDir(), "a.json"), sd, pub, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveCount(a.countPath, [32]byte{3}, 1); err != nil {
		t.Fatal(err)
	}
	_ = a.close()
	b, err := openLogState(filepath.Join(t.TempDir(), "b.json"), sd, pub, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.close() }()
	if b.used != 1 {
		t.Fatalf("count under another log path: %d, want 1", b.used)
	}
}

// A count an earlier version kept beside the log is honoured: the higher wins.
func TestLegacyCountBesideTheLogIsHonoured(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	if err := saveCount(path+".count", [32]byte{4}, 2); err != nil {
		t.Fatal(err)
	}
	st, err := openLogState(path, sd, pub, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	if st.used != 2 {
		t.Fatalf("legacy count: %d, want 2", st.used)
	}
}

// A state directory others can write to is refused.
func TestStateDirMustBeOwnerOnly(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	if err := os.MkdirAll(sd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sd, 0o777); err != nil { // #nosec G302 -- the case under test
		t.Fatal(err)
	}
	if _, err := openLogState(path, sd, pub, [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("group/world-writable state directory: %v", err)
	}
}

// Opening state loads the checkpoint record: a matching one sets the recorded
// head, and one the log does not match stops startup.
func TestOpenStateChecksTheCheckpointRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	l, _ := logWith(t, 3, 0)
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	root, _ := l.Head()
	if err := saveCheckpointHead(path+".checkpoint", 3, root, common.Hash{1}); err != nil {
		t.Fatal(err)
	}
	st, err := openLogState(path, testState(t), l.PublicKey(), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if st.published != 3 {
		t.Fatalf("recorded head from state: %d, want 3", st.published)
	}
	_ = st.close()
	if err := saveCheckpointHead(path+".checkpoint", 3, [32]byte{9}, common.Hash{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogState(path, testState(t), l.PublicKey(), [32]byte{1}); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("mismatched record at startup: %v", err)
	}
}

// §6: a checkpoint is recorded only once it is mined; one not seen mined is
// published again by the next run.
func TestCheckpointRecordedOnlyWhenMined(t *testing.T) {
	fake, cp, l, _ := checkpointFixture(t)
	fake.Set(func(f *arcpaytest.Fake) { f.NoReceipt = true })
	_ = cp.publish(1500*time.Millisecond, true)
	if len(fake.Broadcasts()) != 1 {
		t.Fatalf("broadcasts: %d", len(fake.Broadcasts()))
	}
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 0 {
		t.Fatalf("recorded a checkpoint that was not seen mined: %d", n)
	}
	next := newCheckpointer(cp.net, cp.client, cp.key, l, 1, cp.savedSize, 0, cp.headPath, io.Discard)
	fake.Set(func(f *arcpaytest.Fake) { f.NoReceipt = false })
	next.publishNow()
	if len(fake.Broadcasts()) != 2 {
		t.Fatalf("the next run did not publish the unrecorded head: %d broadcasts", len(fake.Broadcasts()))
	}
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 3 {
		t.Fatalf("mined checkpoint not recorded: %d", n)
	}
}

// A reverted checkpoint is not recorded and is sent again.
func TestRevertedCheckpointIsSentAgain(t *testing.T) {
	fake, cp, l, _ := checkpointFixture(t)
	fake.Set(func(f *arcpaytest.Fake) { f.ReceiptStatus = 0 })
	cp.publishNow()
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 0 {
		t.Fatalf("recorded a reverted checkpoint: %d", n)
	}
	fake.Set(func(f *arcpaytest.Fake) { f.ReceiptStatus = 1 })
	cp.publishNow()
	if len(fake.Broadcasts()) != 2 {
		t.Fatalf("reverted head not sent again: %d broadcasts", len(fake.Broadcasts()))
	}
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 3 {
		t.Fatalf("mined checkpoint not recorded: %d", n)
	}
}

// §6: save confirms both locks are still in place first; if one is gone,
// nothing is saved and the caller settles nothing.
func TestSaveRefusesWhenALockFileIsGone(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	st, err := openLogState(path, sd, pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	if err := st.save(); err != nil {
		t.Fatalf("save with locks in place: %v", err)
	}
	if err := os.Remove(st.capLock.Name()); err != nil {
		t.Fatal(err)
	}
	st.used = 1
	if err := st.save(); !errors.Is(err, arcpay.ErrUnavailable) {
		t.Fatalf("save after the capability lock file was removed: %v", err)
	}
	if n, _ := loadCount(st.countPath, [32]byte{1}); n != 0 {
		t.Fatalf("count saved without the lock: %d", n)
	}
}

// §3: the count is written in the state directory and beside the log, so a
// gateway on the same log with another state directory still sees it.
func TestCountIsKeptBesideTheLogToo(t *testing.T) {
	path, pub := stateDir(t)
	st, err := openLogState(path, testState(t), pub, [32]byte{5})
	if err != nil {
		t.Fatal(err)
	}
	st.used = 1
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	a, _ := loadCount(st.countPath, [32]byte{5})
	b, _ := loadCount(st.besidePath, [32]byte{5})
	_ = st.close()
	if a != 1 || b != 1 {
		t.Fatalf("counts after save: state %d, beside log %d", a, b)
	}
	again, err := openLogState(path, testState(t), pub, [32]byte{5})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.close() }()
	if again.used != 1 {
		t.Fatalf("same log, other state directory: used %d, want 1", again.used)
	}
}

// §6: with the capability lock held elsewhere, no count is read: the refusal
// is the lock's, not the malformed count's.
func TestNothingIsReadBeforeTheCapabilityLock(t *testing.T) {
	path, pub := stateDir(t)
	sd := testState(t)
	if err := checkStateDir(sd); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(bytes32(6))
	held, err := lockFile(filepath.Join(sd, id+".lock"), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := os.WriteFile(filepath.Join(sd, id+".count"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogState(path, sd, pub, [32]byte{6}); !strings.Contains(errText(err), "another arc-gateway is using capability") {
		t.Fatalf("expected the capability lock refusal before any read, got %v", err)
	}
}

// §6: a sent checkpoint that has been mined is recorded at the next decision,
// without waiting for the next checkpoint to be due.
func TestMinedCheckpointRecordedAtTheNextDecision(t *testing.T) {
	fake, cp, l, _ := checkpointFixture(t)
	if err := cp.publish(5*time.Second, false); err != nil {
		t.Fatal(err)
	}
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 0 {
		t.Fatalf("recorded before it was seen mined: %d", n)
	}
	cp.maybePublish()
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 3 {
		t.Fatalf("mined checkpoint not recorded at the next decision: %d", n)
	}
	if len(fake.Broadcasts()) != 1 {
		t.Fatalf("broadcasts: %d", len(fake.Broadcasts()))
	}
}

// Either lock file gone stops the save: here the log's.
func TestSaveRefusesWhenTheLogLockFileIsGone(t *testing.T) {
	path, pub := stateDir(t)
	st, err := openLogState(path, testState(t), pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := st.save(); !errors.Is(err, arcpay.ErrUnavailable) {
		t.Fatalf("save after the log lock file was removed: %v", err)
	}
}

// A checkpoint still pending at shutdown is waited for and recorded.
func TestPendingCheckpointRecordedAtShutdown(t *testing.T) {
	fake, cp, l, _ := checkpointFixture(t)
	if err := cp.publish(5*time.Second, false); err != nil {
		t.Fatal(err)
	}
	cp.publishNow()
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 3 {
		t.Fatalf("pending checkpoint not recorded at shutdown: %d", n)
	}
	if len(fake.Broadcasts()) != 1 {
		t.Fatalf("shutdown sent the head again: %d broadcasts", len(fake.Broadcasts()))
	}
}

// §5: the checkpoint runs once the reply has been written, and only for a
// call that recorded a decision.
func TestCheckpointRunsAfterTheReply(t *testing.T) {
	used := 0
	s := newTestServer(realEnforcer(t, testCap, &used, func() time.Time { return t0 }), nil, &used)
	var out bytes.Buffer
	s.out = &out
	written := -1
	s.onEntry = func() { written = out.Len() }
	params := []byte(`{"name":"authorize_payment","arguments":{"to":"attacker","amount_usdc":0.5,"resource":"invoice:42"}}`)
	s.handle(context.Background(), rpcReq{JSONRPC: "2.0", ID: []byte("1"), Method: "tools/call", Params: params})
	if written <= 0 {
		t.Fatalf("checkpoint ran before the reply was written (reply bytes seen: %d)", written)
	}
	written = -1
	s.handle(context.Background(), rpcReq{JSONRPC: "2.0", ID: []byte("2"), Method: "tools/list"})
	if written != -1 {
		t.Fatalf("checkpoint ran for a call that recorded no decision")
	}
}

// §6: a count that cannot be written stops the save before the log is
// written, so the log never holds an ALLOW the count lacks.
func TestCountWriteFailureStopsTheSaveBeforeTheLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	l, priv := logWith(t, 1, 0)
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := openLogState(path, testState(t), l.PublicKey(), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	// Replace the count file with a directory: the rename onto it fails.
	if err := os.Remove(st.countPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(st.countPath, 0o700); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := st.log.Append(priv, translog.Allow, [32]byte{7}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	st.used = 1
	if err := st.save(); err == nil {
		t.Fatal("save succeeded although the count could not be written")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("the log was written although the count was not")
	}
}

// §6: a log that cannot be saved fails the save and leaves the saved size, so
// no unsaved head is checkpointed.
func TestLogSaveFailureFailsTheSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.json")
	l, priv := logWith(t, 1, 0)
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := openLogState(path, testState(t), l.PublicKey(), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	if _, err := st.log.Append(priv, translog.Allow, [32]byte{7}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := st.save(); err != nil || st.saved != 2 {
		t.Fatalf("successful save: err %v, saved %d, want 2", err, st.saved)
	}
	if _, err := st.log.Append(priv, translog.Allow, [32]byte{8}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil { // the log's name is now a directory
		t.Fatal(err)
	}
	if err := st.save(); err == nil {
		t.Fatal("save succeeded although the log could not be written")
	}
	if st.saved != 2 {
		t.Fatalf("saved size moved to %d after a failed log save", st.saved)
	}
}

// §6: a lock file replaced by another file stops the save, as a removed one
// does.
func TestSaveRefusesWhenALockFileIsReplaced(t *testing.T) {
	path, pub := stateDir(t)
	st, err := openLogState(path, testState(t), pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	other := path + ".other"
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if err := st.save(); !errors.Is(err, arcpay.ErrUnavailable) {
		t.Fatalf("save after the lock file was replaced: %v", err)
	}
}

// Startup writes the counts, so an unwritable count location refuses there.
func TestStartupRefusesAnUnwritableCount(t *testing.T) {
	path, pub := stateDir(t)
	if err := os.Mkdir(path+"."+hex.EncodeToString(bytes32(1))+".count", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogState(path, testState(t), pub, [32]byte{1}); err == nil {
		t.Fatal("started although the count beside the log cannot be written")
	}
}

// §6: one checkpoint in flight: a newer head waits until the pending one is
// seen mined or reverted.
func TestOneCheckpointInFlight(t *testing.T) {
	fake, cp, l, priv := checkpointFixture(t)
	fake.Set(func(f *arcpaytest.Fake) { f.NoReceipt = true })
	_ = cp.publish(1500*time.Millisecond, false)
	if _, err := l.Append(priv, translog.Allow, [32]byte{8}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	cp.savedSize = func() int { return 4 }
	if err := cp.publish(1500*time.Millisecond, false); err == nil {
		t.Fatal("sent a second checkpoint while the first was unconfirmed")
	}
	if len(fake.Broadcasts()) != 1 {
		t.Fatalf("broadcasts: %d, want 1", len(fake.Broadcasts()))
	}
	fake.Set(func(f *arcpaytest.Fake) { f.NoReceipt = false })
	cp.publishNow()
	if len(fake.Broadcasts()) != 2 {
		t.Fatalf("newer head not sent once the first was mined: %d", len(fake.Broadcasts()))
	}
}

// §3: another capability on the same log keeps its own count and leaves this
// one's alone, so a restart with another state directory still sees it.
func TestOtherCapabilityOnTheLogKeepsItsOwnCount(t *testing.T) {
	path, pub := stateDir(t)
	a, err := openLogState(path, testState(t), pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	a.used = 1
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	_ = a.close()
	b, err := openLogState(path, testState(t), pub, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.save(); err != nil {
		t.Fatal(err)
	}
	_ = b.close()
	again, err := openLogState(path, testState(t), pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.close() }()
	if again.used != 1 {
		t.Fatalf("count after another capability ran on the log: %d, want 1", again.used)
	}
}

// An unkeyed count from an earlier version is read, never written.
func TestLegacyCountIsNeverWritten(t *testing.T) {
	path, pub := stateDir(t)
	if err := saveCount(path+".count", [32]byte{9}, 3); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path + ".count")
	st, err := openLogState(path, testState(t), pub, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.close() }()
	st.used = 1
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path + ".count")
	if !bytes.Equal(before, after) {
		t.Fatal("the legacy count file was rewritten")
	}
}

// Only a call that recorded a decision runs the checkpoint; a call refused
// before any decision does not, including right after one that did.
func TestCheckpointOnlyAfterARecordedDecision(t *testing.T) {
	used := 0
	s := newTestServer(realEnforcer(t, testCap, &used, func() time.Time { return t0 }), nil, &used)
	runs := 0
	s.onEntry = func() { runs++ }
	recorded := []byte(`{"name":"authorize_payment","arguments":{"to":"attacker","amount_usdc":0.5,"resource":"invoice:42"}}`)
	noAmount := []byte(`{"name":"authorize_payment","arguments":{"to":"merchant","resource":"invoice:42"}}`)
	s.handle(context.Background(), rpcReq{JSONRPC: "2.0", ID: []byte("1"), Method: "tools/call", Params: recorded})
	if runs != 1 {
		t.Fatalf("after a recorded decision: %d checkpoint runs, want 1", runs)
	}
	s.handle(context.Background(), rpcReq{JSONRPC: "2.0", ID: []byte("2"), Method: "tools/call", Params: noAmount})
	if runs != 1 {
		t.Fatalf("a call refused before any decision ran the checkpoint (runs %d)", runs)
	}
}

// §6: a checkpoint not seen mined within the timeout is dropped, unrecorded,
// and its head is sent again.
func TestUnseenCheckpointIsSentAgainAfterTimeout(t *testing.T) {
	fake, cp, l, _ := checkpointFixture(t)
	fake.Set(func(f *arcpaytest.Fake) { f.NoReceipt = true })
	start := time.Now()
	cp.now = func() time.Time { return start }
	_ = cp.publish(1500*time.Millisecond, false)
	cp.now = func() time.Time { return start.Add(pendingTimeout + time.Minute) }
	cp.maybePublish()
	if cp.pending != nil {
		t.Fatal("pending checkpoint kept past the timeout")
	}
	if n, _ := loadCheckpointHead(cp.headPath, l); n != 0 {
		t.Fatalf("an unseen checkpoint was recorded: %d", n)
	}
	cp.last = time.Time{}
	_ = cp.publish(1500*time.Millisecond, false)
	if len(fake.Broadcasts()) != 2 {
		t.Fatalf("head not sent again after the timeout: %d broadcasts", len(fake.Broadcasts()))
	}
}

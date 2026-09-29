//go:build arc

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/mcpgate"
	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay/arcpaytest"
)

// F3: the payment count survives a restart for the same capability, starts
// again only for a different one, and a malformed count file is refused.
func TestPaymentCountPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.json.count")
	d1, d2 := [32]byte{1}, [32]byte{2}
	if n, err := loadCount(path, d1); err != nil || n != 0 {
		t.Fatalf("absent file: %d, %v", n, err)
	}
	if err := saveCount(path, d1, 3); err != nil {
		t.Fatal(err)
	}
	if n, err := loadCount(path, d1); err != nil || n != 3 {
		t.Fatalf("same capability after restart: %d, %v", n, err)
	}
	if n, err := loadCount(path, d2); err != nil || n != 0 {
		t.Fatalf("different capability: %d, %v", n, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCount(path, d1); err == nil {
		t.Fatal("a malformed count file was accepted")
	}
}

// F3: an oversized line ends the loop with an error rather than silently.
func TestServeReportsOversizedInput(t *testing.T) {
	used := 0
	s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.DenyViolation}}, (&recorder{}).settle, &used)
	big := strings.Repeat("x", 5*1024*1024)
	if err := s.serve(context.Background(), strings.NewReader(big+"\n")); err == nil {
		t.Fatal("an oversized line ended the loop without an error")
	}
}

// L4: a dry run is never described as a settlement.
func TestDryRunReply(t *testing.T) {
	used := 0
	dry := func(context.Context, arcpay.Payment) (arcpay.Result, error) { return arcpay.Result{}, nil }
	s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "1:ab"}}, dry, &used)
	text, _ := call(s, "merchant", "0.5", "invoice:42")
	if !strings.Contains(text, "DRY RUN") || strings.Contains(text, "settled on Arc") {
		t.Fatalf("dry-run reply: %s", text)
	}
}

func writeKey(t *testing.T, dir, name, hexKey string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hexKey), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// L5: startup refuses the payment key in the checkpoint role.
func TestLoadKeysRefusesOneKeyInBothRoles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory; 0700 is owner-only
		t.Fatal(err)
	}
	k := strings.Repeat("11", 32)
	a := writeKey(t, dir, "a.key", k)
	b := writeKey(t, dir, "b.key", k)
	if _, _, err := loadKeys(a, b); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("the same key in both roles: %v", err)
	}
	c := writeKey(t, dir, "c.key", strings.Repeat("22", 32))
	if _, _, err := loadKeys(a, c); err != nil {
		t.Fatal(err)
	}
}

// L5: a log signed by another key is refused at startup.
func TestOpenLogRefusesAnotherKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.json")
	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)
	if _, err := openLog(path, pubA); err != nil {
		t.Fatal(err)
	}
	if _, err := openLog(path, pubA); err != nil {
		t.Fatalf("reopening with the same key: %v", err)
	}
	if _, err := openLog(path, pubB); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatalf("a log signed by another key: %v", err)
	}
}

func checkpointFixture(t *testing.T) (*arcpaytest.Fake, *checkpointer, *translog.Log, ed25519.PrivateKey) {
	t.Helper()
	net := evm.ArcTestnet()
	fake := arcpaytest.New(net.ChainID)
	t.Cleanup(fake.Close)
	c, err := ethclient.Dial(fake.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	k, _ := crypto.GenerateKey()
	pub, priv, _ := ed25519.GenerateKey(nil)
	l := translog.NewLog(pub)
	saved := 0
	cp := newCheckpointer(net, c, k, l, 1, func() int { return saved }, 0, filepath.Join(t.TempDir(), "log.checkpoint"), io.Discard)
	for i := 0; i < 3; i++ {
		if _, err := l.Append(priv, translog.Allow, [32]byte{byte(i)}, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	saved = 3
	return fake, cp, l, priv
}

// L5: a checkpoint is exactly a 70-byte, zero-value transaction to the
// checkpoint key's own address, carrying the saved head.
func TestCheckpointPublishesTheSavedHead(t *testing.T) {
	fake, cp, l, _ := checkpointFixture(t)
	cp.publishNow()
	sent := fake.Broadcasts()
	if len(sent) != 1 {
		t.Fatalf("%d checkpoints sent", len(sent))
	}
	tx := sent[0]
	root, n := l.Head()
	from := crypto.PubkeyToAddress(cp.key.PublicKey)
	if n <= 0 {
		t.Fatalf("head size %d", n)
	}
	if tx.To() == nil || *tx.To() != from || tx.Value().Sign() != 0 || string(tx.Data()) != string(evm.CheckpointData(uint64(n), root)) { // #nosec G115 -- n > 0
		t.Fatalf("checkpoint transaction: to=%v value=%v data=%x", tx.To(), tx.Value(), tx.Data())
	}
	cp.publishNow()
	if len(fake.Broadcasts()) != 1 {
		t.Fatal("the same head was checkpointed twice")
	}
}

// L2: an unsaved head is never published.
func TestCheckpointSkipsAnUnsavedHead(t *testing.T) {
	fake, cp, l, priv := checkpointFixture(t)
	if _, err := l.Append(priv, translog.Allow, [32]byte{9}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	cp.publishNow() // saved size is still 3; the head is 4
	if len(fake.Broadcasts()) != 0 {
		t.Fatal("an unsaved head was published")
	}
}

// A hostile checkpoint endpoint gets nothing sent, and each hostile answer is
// refused by the control meant for it, not merely by a later layer.
func TestCheckpointRefusesHostileEndpoint(t *testing.T) {
	cases := []struct {
		name string
		set  func(*arcpaytest.Fake)
		want string
	}{
		{"wrong chain", func(f *arcpaytest.Fake) { f.ChainID = evm.ArcMainnetChainID }, "different network"},
		{"fee too high", func(f *arcpaytest.Fake) { f.BaseFee = new(big.Int).Exp(big.NewInt(10), big.NewInt(15), nil) }, "refusing to sign"},
		{"nonce gap", func(f *arcpaytest.Fake) { f.PendingNonce = 4 }, "pending nonce"},
		{"absurd gas", func(f *arcpaytest.Fake) { f.Gas = arcpay.MaxGasLimit + 1 }, "estimated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake, cp, _, _ := checkpointFixture(t)
			fake.Set(c.set)
			err := cp.publish(5*time.Second, false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, c.want)
			}
			if len(fake.Broadcasts()) != 0 {
				t.Fatal("a checkpoint was sent through a hostile endpoint")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A reply that cannot be written is reported to the operator, not dropped.
func TestProtocolWriteFailureIsReported(t *testing.T) {
	used := 0
	var diag strings.Builder
	s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.DenyViolation}}, (&recorder{}).settle, &used)
	s.out, s.diag = failingWriter{}, &diag
	_ = s.serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"))
	if !strings.Contains(diag.String(), "protocol write failed") {
		t.Fatalf("a failed reply was not reported: %q", diag.String())
	}
}

// The count cannot be silently lost: a count file that cannot be written is an
// error, which the server turns into "nothing settled".
func TestSaveCountFailureIsAnError(t *testing.T) {
	if err := saveCount(filepath.Join(t.TempDir(), "missing-dir", "log.json.count"), [32]byte{1}, 1); err == nil {
		t.Fatal("a count that could not be written was reported as saved")
	}
}

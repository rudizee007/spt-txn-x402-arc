//go:build arc

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/mcpgate"

	"github.com/rudizee007/spt-txn-x402-arc/correlation"
	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009/eip3009sign"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

const identity = "arc-gateway-testnet"

var (
	logSeed     = [32]byte{4, 2}
	logEntryHex = sha256.Sum256([]byte("log entry 0"))
	pidA        = strings.Repeat("ab", 32)
)

// hookingRecorder is a settler that, like arcpay, runs the payment's BeforeSign
// hook with a signing hash and settles only if the hook succeeds.
type hookingRecorder struct {
	recorder
	hash common.Hash
}

func (h *hookingRecorder) settle(ctx context.Context, p arcpay.Payment) (arcpay.Result, error) {
	if p.BeforeSign != nil {
		if err := p.BeforeSign(h.hash); err != nil {
			return arcpay.Result{}, err
		}
	}
	return h.recorder.settle(ctx, p)
}

func newM3(t *testing.T, rail string) *m3 {
	t.Helper()
	logKey := ed25519.NewKeyFromSeed(logSeed[:])
	cf, err := correlation.Open(filepath.Join(t.TempDir(), "correlation"), logKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cf.Close() })
	return &m3{
		identity: identity, corr: cf, logKey: logKey, rail: rail, txRail: correlation.RailLocalKeyTx,
		logHash: func(seq uint64) ([32]byte, bool) { return logEntryHex, seq == 0 },
	}
}

func m3Call(s *server, args string) (string, bool) {
	params := []byte(`{"name":"` + s.toolName() + `","arguments":` + args + `}`)
	res := s.toolsCall(context.Background(), params).(map[string]interface{})
	return res["content"].([]interface{})[0].(map[string]interface{})["text"].(string), res["isError"].(bool)
}

func argsM3(pid, ident string) string {
	return `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42","payment_id":"` + pid + `","server_identity":"` + ident + `"}`
}

func allowAt0() *fixedAuthorizer {
	return &fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "0:abcdef"}}
}

func TestM3RefusesBeforeTheDecision(t *testing.T) {
	cases := map[string]string{
		"payment_id absent":          `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42","server_identity":"` + identity + `"}`,
		"server_identity absent":     `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42","payment_id":"` + pidA + `"}`,
		"another gateway's identity": argsM3(pidA, "arc-gateway-mainnet"),
		"identity differs in case":   argsM3(pidA, "Arc-Gateway-Testnet"),
		"payment_id uppercase":       argsM3(strings.ToUpper(pidA), identity),
		"payment_id short":           argsM3(pidA[:62], identity),
		"payment_id not hex":         argsM3(strings.Repeat("zz", 32), identity),
		"payment_id zero":            argsM3(strings.Repeat("00", 32), identity),
	}
	for name, args := range cases {
		rec := &hookingRecorder{}
		auth := allowAt0()
		s := newTestServer(auth, rec.settle, new(int))
		s.m3 = newM3(t, railTransfer)
		if text, isErr := m3Call(s, args); !isErr || len(auth.seen) != 0 || len(rec.calls) != 0 {
			t.Errorf("%s: reached the decision or settled: %s", name, firstLine(text))
		}
	}
}

func TestM3TransferRailRecordsBeforeSigningAndRefusesARepeat(t *testing.T) {
	rec := &hookingRecorder{hash: common.Hash{0x51}}
	auth := allowAt0()
	s := newTestServer(auth, rec.settle, new(int))
	s.m3 = newM3(t, railTransfer)
	// Whitespace and member order differ from canonical form: the digest is of
	// the value, computed over the arguments as received.
	args := ` { "server_identity":"` + identity + `", "payment_id":"` + pidA + `", "resource":"invoice:42", "amount_usdc":"0.5", "to":"merchant" } `
	if text, isErr := m3Call(s, args); isErr || len(rec.calls) != 1 {
		t.Fatalf("allowed call did not settle: %s", text)
	}
	rs := s.m3.corr.Records()
	if len(rs) != 1 {
		t.Fatalf("%d correlation records", len(rs))
	}
	want, err := intent.Compute(s.toolName(), []byte(argsM3(pidA, identity)), identity)
	if err != nil {
		t.Fatal(err)
	}
	r := rs[0]
	pid, _ := hex.DecodeString(pidA)
	if r.IntentDigest != [32]byte(want) || r.LogSeq != 0 || r.LogRecordHash != logEntryHex || r.Rail != correlation.RailLocalKeyTx ||
		r.GuardedID != [32]byte(rec.hash) || r.TargetHash != correlation.TargetHash(identity) || string(r.PaymentID[:]) != string(pid) {
		t.Fatalf("correlation record %+v", r)
	}
	// The same payment_id again: refused before the enforcement point.
	if text, isErr := m3Call(s, argsM3(pidA, identity)); !isErr || len(auth.seen) != 1 || len(rec.calls) != 1 {
		t.Fatalf("repeated payment_id: %s", firstLine(text))
	}
}

// §6.3: if the correlation record cannot be persisted, nothing is signed.
func TestM3NothingIsSignedWithoutACorrelationRecord(t *testing.T) {
	rec := &hookingRecorder{hash: common.Hash{1}}
	s := newTestServer(allowAt0(), rec.settle, new(int))
	s.m3 = newM3(t, railTransfer)
	s.m3.corr.Close()
	if text, isErr := m3Call(s, argsM3(pidA, identity)); !isErr || len(rec.calls) != 0 {
		t.Fatalf("settled without a correlation record: %s", firstLine(text))
	}
	// A log locator that names no log entry is refused the same way.
	s2 := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "7:abcdef"}}, rec.settle, new(int))
	s2.m3 = newM3(t, railTransfer)
	if text, isErr := m3Call(s2, argsM3(pidA, identity)); !isErr || len(rec.calls) != 0 {
		t.Fatalf("settled against a missing log entry: %s", firstLine(text))
	}
}

func eipServer(t *testing.T, auth authorizer, key *ecdsa.PrivateKey) (*server, *int) {
	t.Helper()
	signs := new(int)
	s := newTestServer(auth, nil, new(int))
	m := newM3(t, railEIP3009)
	m.domain = eip3009.Domain{Name: "USDC", Version: "2", ChainID: testCap.Net.ChainID, VerifyingContract: testCap.Net.USDC}
	m.maxLife = 5 * time.Minute
	m.payer = evm.Address(crypto.PubkeyToAddress(key.PublicKey))
	m.signEIP = func(_ context.Context, b eip3009.Bound) ([]byte, error) { *signs++; return eip3009sign.Sign(b, key) }
	s.m3 = m
	return s, signs
}

func testECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestM3EIP3009RailSignsTheBoundAuthorization(t *testing.T) {
	k := testECDSA(t)
	s, signs := eipServer(t, allowAt0(), k)
	text, isErr := m3Call(s, argsM3(pidA, identity))
	if isErr || *signs != 1 {
		t.Fatalf("eip3009 rail: %s", text)
	}
	i := strings.Index(text, "payload: ")
	var p x402Payload
	if i < 0 || json.Unmarshal([]byte(text[i+len("payload: "):]), &p) != nil {
		t.Fatalf("no payload in %q", text)
	}
	d, _ := intent.Compute(s.toolName(), []byte(argsM3(pidA, identity)), identity)
	n := intent.EIP3009Nonce(d)
	if p.Authorization["nonce"] != "0x"+hex.EncodeToString(n[:]) || p.Authorization["to"] != common.Address(testCap.Recipient).Hex() ||
		p.Authorization["value"] != "500000" || p.Authorization["from"] != crypto.PubkeyToAddress(k.PublicKey).Hex() {
		t.Fatalf("payload %+v", p)
	}
	vb, _ := new(big.Int).SetString(p.Authorization["validBefore"], 10)
	if vb.Int64() > t0.Add(time.Minute).Unix() {
		t.Fatalf("validBefore %s outlives the call expiry", vb)
	}
	rs := s.m3.corr.Records()
	if len(rs) != 1 || rs[0].Rail != correlation.RailEIP3009 || rs[0].IntentDigest != [32]byte(d) {
		t.Fatalf("correlation %+v", rs)
	}
}

func TestM3EIP3009RailRefusals(t *testing.T) {
	k := testECDSA(t)
	// The enforcement point (wrongly) allows the attacker: the rail refuses alone.
	s, signs := eipServer(t, allowAt0(), k)
	if text, isErr := m3Call(s, `{"to":"attacker","amount_usdc":"0.5","resource":"invoice:42","payment_id":"`+pidA+`","server_identity":"`+identity+`"}`); !isErr || *signs != 0 {
		t.Fatalf("signed for an unapproved recipient: %s", firstLine(text))
	}
	// No correlation record, no signature.
	s2, signs2 := eipServer(t, allowAt0(), k)
	s2.m3.corr.Close()
	if text, isErr := m3Call(s2, argsM3(pidA, identity)); !isErr || *signs2 != 0 || !strings.Contains(text, "DENY_UNAVAILABLE") {
		t.Fatalf("signed without a correlation record: %s", firstLine(text))
	}
	// A refusal by the enforcement point signs nothing and records nothing.
	s3, signs3 := eipServer(t, &fixedAuthorizer{res: mcpgate.Result{Class: gate.DenyViolation, LogEntry: "0:abcdef"}}, k)
	if _, isErr := m3Call(s3, argsM3(pidA, identity)); !isErr || *signs3 != 0 || s3.m3.corr.Len() != 0 {
		t.Fatal("a DENY produced a signature or a correlation record")
	}
	// A signer that returns a signature by another key is refused.
	s4, _ := eipServer(t, allowAt0(), k)
	other := testECDSA(t)
	s4.m3.signEIP = func(_ context.Context, b eip3009.Bound) ([]byte, error) {
		d := b.Digest()
		sig, _ := crypto.Sign(d[:], other)
		sig[64] += 27
		return sig, eip3009sign.Check(b, sig)
	}
	if text, isErr := m3Call(s4, argsM3(pidA, identity)); !isErr || strings.Contains(text, "payload") {
		t.Fatalf("a signature by another key was handed out: %s", firstLine(text))
	}
}

func TestCheckServerIdentity(t *testing.T) {
	for _, ok := range []string{"arc-gateway-testnet", "gw.example/1", "ziel-€"} {
		if err := checkServerIdentity(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " gw", "gw ", "g\nw", "g\x00w", "g�w", strings.Repeat("a", 257), "g\x7fw"} {
		if err := checkServerIdentity(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

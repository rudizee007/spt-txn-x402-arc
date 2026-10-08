//go:build arc

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rudizee007/spt-txn-x402-arc/correlation"
	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009/eip3009sign"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/x402v2"
)

// SPEC-ARC-M3 wiring. A server runs in M3 mode when it is given a server
// identity. The payment tool then also takes payment_id and server_identity.
// The intent digest is recomputed over the arguments as received, and a
// correlation record is persisted before anything is signed.

// Rails (one per process).
const (
	railTransfer = "transfer" // the M2 ERC-20 transfer, signed by a local key or a Circle wallet
	railEIP3009  = "eip3009"  // an x402 exact authorization for a facilitator to submit
)

// m3Args are the arguments M3 mode adds to the payment tool.
var m3Args = []string{"payment_id", "server_identity"}

// eip3009Objects are the object-valued arguments the EIP-3009 rail adds: the
// resource server's payment requirements (x402 v2 `accepted`) and its resource
// object, both echoed into the payload after validation (§4.1.5). They are part
// of the arguments object, so the intent digest covers them.
var eip3009Objects = []string{"x402_accepted", "x402_resource"}

// maxTimeoutCeiling bounds accepted.maxTimeoutSeconds (§4.1.5).
const maxTimeoutCeiling = 300

type m3 struct {
	identity string
	corr     *correlation.File
	logKey   ed25519.PrivateKey
	logHash  func(seq uint64) ([32]byte, bool)
	rail     string
	txRail   byte // correlation rail for railTransfer: local key or Circle wallet

	// railEIP3009 only.
	domain  eip3009.Domain
	maxLife time.Duration
	payer   evm.Address
	signEIP func(context.Context, eip3009.Bound) ([]byte, error) // nil in evaluate-only and dry-run
	x402    x402v2.Config
	// complete persists the 0x02 completion record (§6.3). nil uses the
	// correlation file; tests substitute one to fail or observe the write.
	complete func(refSeq uint64, payloadSHA256 [32]byte) (correlation.Completion, error)
}

// pendingRelease is a payload whose completion record is persisted and which
// the reply now being written carries. server.handle reports what became of it.
type pendingRelease struct {
	locator      string
	refSeq       uint64
	completedSeq uint64
	sha          [32]byte
}

// checkServerIdentity applies the startup rules (§2): non-empty, no leading or
// trailing whitespace, no control characters, valid UTF-8, at most 256 bytes.
func checkServerIdentity(s string) error {
	switch {
	case s == "":
		return errors.New("-server-identity is empty")
	case strings.TrimSpace(s) != s:
		return errors.New("-server-identity has leading or trailing whitespace")
	case len(s) > 256:
		return errors.New("-server-identity is longer than 256 bytes")
	case !isPrintableUTF8(s):
		return errors.New("-server-identity contains a control character or invalid UTF-8")
	}
	return nil
}

func isPrintableUTF8(s string) bool {
	for _, r := range s {
		if r == unicode.ReplacementChar || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// precheck runs before the enforcement decision. It checks the call names this
// server's identity and carries a fresh payment_id, and computes the intent
// digest over the arguments as received (§6.1).
func (m *m3) precheck(tc toolCall) (intent.Digest, [32]byte, error) {
	var pid [32]byte
	if tc.Args["server_identity"] != m.identity {
		return intent.Digest{}, pid, errors.New("server_identity does not name this gateway")
	}
	p := tc.Args["payment_id"]
	if len(p) != 64 || strings.ToLower(p) != p {
		return intent.Digest{}, pid, errors.New("payment_id must be 64 lowercase hexadecimal characters")
	}
	if _, err := hex.Decode(pid[:], []byte(p)); err != nil {
		return intent.Digest{}, pid, errors.New("payment_id must be 64 lowercase hexadecimal characters")
	}
	if pid == ([32]byte{}) {
		return intent.Digest{}, pid, errors.New("payment_id must not be zero")
	}
	if m.corr.Seen(pid) {
		return intent.Digest{}, pid, errors.New("payment_id has already been used")
	}
	d, err := intent.Compute(tc.Name, tc.RawArguments, m.identity)
	if err != nil {
		return intent.Digest{}, pid, err
	}
	return d, pid, nil
}

// record persists the correlation record for an allowed decision, before the
// artefact identified by guarded is signed (§6.3). It returns the record's
// sequence number in the correlation chain.
func (m *m3) record(locator string, d intent.Digest, pid [32]byte, rail byte, guarded [32]byte) (uint64, error) {
	seqStr, _, ok := strings.Cut(locator, ":")
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if !ok || err != nil {
		return 0, fmt.Errorf("log locator %q is malformed", locator)
	}
	h, ok := m.logHash(seq)
	if !ok {
		return 0, fmt.Errorf("log entry %d is not in the log", seq)
	}
	r, err := m.corr.Append(correlation.Record{
		LogSeq: seq, LogRecordHash: h, IntentDigest: d, PaymentID: pid,
		TargetHash: correlation.TargetHash(m.identity), Rail: rail, GuardedID: guarded,
	}, m.logKey)
	return r.Seq, err
}

// beforeSign is the arcpay hook for the transfer rail.
func (m *m3) beforeSign(locator string, d intent.Digest, pid [32]byte) func(common.Hash) error {
	return func(h common.Hash) error {
		_, err := m.record(locator, d, pid, m.txRail, h)
		return err
	}
}

func (m *m3) completion(refSeq uint64, sha [32]byte) (correlation.Completion, error) {
	if m.complete != nil {
		return m.complete(refSeq, sha)
	}
	return m.corr.AppendCompletion(refSeq, sha, m.logKey)
}

// authorizeEIP3009 validates the resource server's requirements, binds, records
// and signs the EIP-3009 authorization for an allowed call, builds the x402 v2
// payload and persists its completion record. It never broadcasts: a
// facilitator submits the payload.
//
// Order (§4.1.5, §6.3), each step only if the one before it succeeded:
//
//  1. bind the authorization and check the requirements against it and the
//     pinned configuration (nothing recorded, nothing signed on a refusal);
//  2. persist the layout-0x01 correlation record;
//  3. signing attempted: ask the signer once;
//  4. recover the signer, build the payload, hash its exact bytes;
//  5. completion recorded: persist the layout-0x02 record;
//  6. release: the payload goes into the reply. server.handle reports
//     "release attempted" and, if the write fails, "release outcome unknown".
//
// A failure after step 3 never retries signing: the outcome of a signing
// request that returned an error is not established (a remote signer may have
// produced a signature), the payment_id is consumed by step 2, and the agent
// needs a fresh call. A failure after step 3 never releases anything.
func (s *server) authorizeEIP3009(ctx context.Context, locator string, d intent.Digest, pid [32]byte, to evm.Address, micro uint64, callExpiry time.Time, objects map[string]json.RawMessage) (string, bool) {
	m := s.m3
	if to != s.cap.Recipient {
		// The policy refuses this already; the rail refuses it on its own (I3).
		return "DENY_VIOLATION: the authorized recipient is not the approved recipient; nothing was signed", true
	}
	b, err := eip3009.Bind(eip3009.Binding{
		Domain: m.domain, From: m.payer, To: s.cap.Recipient, Value: new(big.Int).SetUint64(micro), Intent: d,
		CapabilityExpiry: s.cap.ExpiresAt, CallExpiry: callExpiry, MaxLifetime: m.maxLife,
	}, s.now())
	if err != nil {
		return "DENY_VIOLATION: " + err.Error() + "; nothing was signed", true
	}
	accepted, resource := objects["x402_accepted"], objects["x402_resource"]
	if err := x402v2.Check(m.x402, b, accepted, resource); err != nil {
		return "DENY_VIOLATION: payment requirements: " + err.Error() + "; nothing was recorded or signed", true
	}
	refSeq, err := m.record(locator, d, pid, correlation.RailEIP3009, b.Digest())
	if err != nil {
		_, _ = fmt.Fprintf(s.diag, "EVIDENCE FAILURE: correlation record not persisted: %v\n", err)
		return "DENY_UNAVAILABLE: the correlation record could not be persisted, so nothing was signed", true
	}
	if s.mode == modeDryRun || m.signEIP == nil {
		return fmt.Sprintf("AUTHORIZED (log entry %s). DRY RUN: the EIP-3009 guard and the payment requirements passed; nothing was signed.", locator), false
	}
	_, _ = fmt.Fprintf(s.diag, "signing attempted: log entry %s, correlation record %d, payment_id %x\n", locator, refSeq, pid)
	const noRetry = "The signing outcome is not established and is not retried; payment_id %x is consumed; no payload was released."
	sig, err := m.signEIP(ctx, b)
	if err != nil {
		_, _ = fmt.Fprintf(s.diag, "EIP-3009 signing after ALLOW %s failed: %v. "+noRetry+"\n", locator, err, pid)
		return fmt.Sprintf("AUTHORIZED (log entry %s), but no acceptable signature was produced: %s. "+noRetry,
			locator, firstLine(err.Error()), pid), true
	}
	withheld := func(what string, err error) (string, bool) {
		_, _ = fmt.Fprintf(s.diag, "PAYLOAD WITHHELD after signing for log entry %s (correlation record %d): %s: %v. Signing is not retried; payment_id %x is consumed.\n",
			locator, refSeq, what, err, pid)
		return fmt.Sprintf("DENY_UNAVAILABLE: AUTHORIZED (log entry %s) and signed, but %s; the payload is withheld and discarded. "+
			"Signing is not retried; payment_id %x is consumed.", locator, what, pid), true
	}
	recovered, err := eip3009sign.Recover(b.Digest(), sig)
	if err != nil {
		return withheld("the signature does not recover", err)
	}
	p, err := x402v2.Build(m.x402, b, sig, recovered, accepted, resource)
	if err != nil {
		return withheld("the payload could not be built", err)
	}
	c, err := m.completion(refSeq, p.SHA256)
	if err != nil {
		return withheld("the completion record could not be persisted", err)
	}
	_, _ = fmt.Fprintf(s.diag, "completion recorded: correlation record %d completes %d, payload_sha256 %x\n", c.Seq, refSeq, p.SHA256)
	s.release = &pendingRelease{locator: locator, refSeq: refSeq, completedSeq: c.Seq, sha: p.SHA256}
	return fmt.Sprintf("AUTHORIZED by the SPT-Txn enforcement point; EIP-3009 authorization signed through the guard. "+
		"Not broadcast: a facilitator submits it. The completion record evidences that this payload was produced for this "+
		"authorization; it is not evidence of receipt, settlement or delivery.\n"+
		"  log entry: %s\n  intent digest: %s\n  correlation: authorization %d, completion %d\n"+
		"  payload_sha256: %x\n  PAYMENT-SIGNATURE: %s\n  payload: %s",
		locator, d, refSeq, c.Seq, p.SHA256, p.Header, p.JSON), false
}

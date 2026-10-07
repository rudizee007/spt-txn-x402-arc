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
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
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
// artefact identified by guarded is signed (§6.3).
func (m *m3) record(locator string, d intent.Digest, pid [32]byte, rail byte, guarded [32]byte) error {
	seqStr, _, ok := strings.Cut(locator, ":")
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if !ok || err != nil {
		return fmt.Errorf("log locator %q is malformed", locator)
	}
	h, ok := m.logHash(seq)
	if !ok {
		return fmt.Errorf("log entry %d is not in the log", seq)
	}
	_, err = m.corr.Append(correlation.Record{
		LogSeq: seq, LogRecordHash: h, IntentDigest: d, PaymentID: pid,
		TargetHash: correlation.TargetHash(m.identity), Rail: rail, GuardedID: guarded,
	}, m.logKey)
	return err
}

// beforeSign is the arcpay hook for the transfer rail.
func (m *m3) beforeSign(locator string, d intent.Digest, pid [32]byte) func(common.Hash) error {
	return func(h common.Hash) error { return m.record(locator, d, pid, m.txRail, h) }
}

// x402Payload is what the EIP-3009 rail hands back: the signed authorization in
// the x402 exact EVM payload shape (V-1: to be confirmed against the x402
// version the facilitator implements).
type x402Payload struct {
	Signature     string            `json:"signature"`
	Authorization map[string]string `json:"authorization"`
}

// authorizeEIP3009 binds, records and signs the EIP-3009 authorization for an
// allowed call. It never broadcasts: a facilitator submits it.
func (s *server) authorizeEIP3009(ctx context.Context, locator string, d intent.Digest, pid [32]byte, to evm.Address, micro uint64, callExpiry time.Time) (string, bool) {
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
	if err := m.record(locator, d, pid, correlation.RailEIP3009, b.Digest()); err != nil {
		_, _ = fmt.Fprintf(s.diag, "EVIDENCE FAILURE: correlation record not persisted: %v\n", err)
		return "DENY_UNAVAILABLE: the correlation record could not be persisted, so nothing was signed", true
	}
	if s.mode == modeDryRun || m.signEIP == nil {
		return fmt.Sprintf("AUTHORIZED (log entry %s). DRY RUN: the EIP-3009 guard passed; nothing was signed.", locator), false
	}
	sig, err := m.signEIP(ctx, b)
	if err != nil {
		_, _ = fmt.Fprintf(s.diag, "EIP-3009 signing after ALLOW %s failed: %v\n", locator, err)
		return fmt.Sprintf("AUTHORIZED (log entry %s), but no acceptable signature was produced: %s", locator, firstLine(err.Error())), true
	}
	a := b.Authorization()
	out, err := json.Marshal(x402Payload{
		Signature: "0x" + hex.EncodeToString(sig),
		Authorization: map[string]string{
			"from": common.Address(a.From).Hex(), "to": common.Address(a.To).Hex(), "value": a.Value.String(),
			"validAfter": a.ValidAfter.String(), "validBefore": a.ValidBefore.String(),
			"nonce": "0x" + hex.EncodeToString(a.Nonce[:]),
		},
	})
	if err != nil {
		return "DENY_UNAVAILABLE: could not encode the authorization", true
	}
	return fmt.Sprintf("AUTHORIZED by the SPT-Txn enforcement point; EIP-3009 authorization signed through the guard (not broadcast; a facilitator submits it).\n"+
		"  log entry: %s\n  intent digest: %s\n  payload: %s", locator, d, out), false
}

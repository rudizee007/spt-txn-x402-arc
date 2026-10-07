//go:build arc

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rudizee007/spt-txn-pep/amount"
	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/mcpgate"

	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// This server is deliberately thin (SPEC-ARC-GATE §1): MCP protocol handling,
// the approved capability, and the hand-off from an authorized decision to the
// shared settler. The decision is mcpgate's; the amount grammar is
// spt-txn-pep/amount's; the transaction assertions are settle/evm's.

// attackerAddress is the demo label an agent can be told to pay. It is never
// the approved recipient, so a call that names it is refused by the policy.
var attackerAddress = evm.MustParseAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

// authorizer is the enforcement point. *mcpgate.Enforcer satisfies it; tests
// substitute one to prove the settler refuses on its own (SPEC-ARC-GATE I3).
type authorizer interface {
	Authorize(mcpgate.ToolCall) mcpgate.Result
}

// settleFunc pays an authorized payment. In production it is arcpay.Settle.
type settleFunc func(context.Context, arcpay.Payment) (arcpay.Result, error)

// Modes (SPEC-ARC-GATE §6a). Fixed at startup; the tool an agent sees and the
// first line of every reply follow from it.
const (
	modeLive     = "live"
	modeDryRun   = "dry-run"
	modeEvaluate = "evaluate-only"
)

type server struct {
	mode    string // modeLive, modeDryRun or modeEvaluate
	cap     capability
	enf     authorizer
	settle  settleFunc
	persist func() error // persist the log and the payment count after every decision (§6)
	onEntry func()       // called after every recorded decision (checkpoints, §5)
	entered bool         // a decision was recorded by the call being answered
	now     func() time.Time
	used    *int // ALLOWs issued under this capability; shared with the policy
	out     io.Writer
	diag    io.Writer
	m3      *m3 // SPEC-ARC-M3 mode; nil runs the M2 gateway unchanged
}

// countingPolicy is the capability's policy: the approved payment shape
// (mcpgate.ExactPayment) and at most MaxPayments ALLOWs. It sits inside the
// enforcement point, so a refusal for an exhausted capability is a recorded
// DENY like any other, not a silent gateway-side drop.
type countingPolicy struct {
	exact mcpgate.ExactPayment
	max   int
	used  *int
}

func (c countingPolicy) Verify(pr gate.PaymentRequirements, t gate.Token) error {
	if *c.used >= c.max {
		return fmt.Errorf("capability used up: %d of %d payments already authorized", *c.used, c.max)
	}
	return c.exact.Verify(pr, t)
}

// ── JSON-RPC 2.0 over stdio ─────────────────────────────────────────────────

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

func (s *server) write(v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	if _, err := s.out.Write(append(b, '\n')); err != nil {
		// The client cannot receive the reply. Say so where an operator looks;
		// the decision, if any, is already recorded.
		_, _ = fmt.Fprintf(s.diag, "protocol write failed: %v\n", err)
	}
}

func (s *server) serve(ctx context.Context, in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		s.handle(ctx, req)
	}
	// An oversized line or a read error ends the loop. Report it rather than
	// returning as if the client had closed the stream.
	return sc.Err()
}

func (s *server) handle(ctx context.Context, req rpcReq) {
	isRequest := len(req.ID) > 0 // requests have an id; notifications don't
	reply := func(result interface{}) { s.write(rpcResp{JSONRPC: "2.0", ID: req.ID, Result: result}) }
	switch req.Method {
	case "initialize":
		ver := "2024-11-05"
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(req.Params, &p) == nil && p.ProtocolVersion != "" {
			ver = p.ProtocolVersion
		}
		reply(map[string]interface{}{
			"protocolVersion": ver,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]interface{}{"name": "spt-txn-arc-gateway", "version": "0.1.0"},
		})
	case "tools/list":
		reply(s.toolsList())
	case "tools/call":
		reply(s.toolsCall(ctx, req.Params))
		// The checkpoint runs once the reply is written, so it never delays
		// the answer or a payment toward its expiry (§5).
		if s.entered {
			s.entered = false
			if s.onEntry != nil {
				s.onEntry()
			}
		}
	case "resources/list":
		reply(map[string]interface{}{"resources": []interface{}{}})
	case "prompts/list":
		reply(map[string]interface{}{"prompts": []interface{}{}})
	case "ping":
		reply(map[string]interface{}{})
	case "notifications/initialized", "notifications/cancelled":
	default:
		if isRequest {
			s.write(rpcResp{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{Code: -32601, Message: "method not found: " + req.Method}})
		}
	}
}

// toolName is the one tool this server offers: evaluate_payment in
// evaluate-only mode, authorize_payment in live and dry-run mode. The two never
// coexist, and a server in any other mode offers no tool at all.
func (s *server) toolName() string {
	switch s.mode {
	case modeEvaluate:
		return "evaluate_payment"
	case modeLive, modeDryRun:
		return "authorize_payment"
	}
	return ""
}

// payments states what an ALLOW does to a payment in this mode.
func (s *server) payments() string {
	switch s.mode {
	case modeLive:
		return "settled on ALLOW"
	case modeDryRun:
		return "guard only, nothing signed"
	}
	return "no payment key, none can be sent"
}

// checkpoints states whether log checkpoints are published. They are the only
// transactions a dry-run or evaluate-only server sends; they carry no value and
// are signed with their own key, which pays their gas.
func (s *server) checkpoints() string {
	if s.onEntry != nil {
		return "on, from a separate gas-only key"
	}
	return "off"
}

func (s *server) toolDescription() string {
	policy := "It is allowed only if it matches the one capability a human approved: recipient, " +
		"resource, a maximum amount and an expiry. Every decision, allowed or refused, is recorded " +
		"in a signed transparency log whose head is checkpointed on Arc."
	switch s.mode {
	case modeEvaluate:
		return "Ask the SPT-Txn enforcement point whether a proposed USDC payment on Arc would be " +
			"allowed, and why. Evaluate-only: this server holds NO payment key and cannot sign or " +
			"send any payment, so calling this tool cannot make a payment. The only transactions it " +
			"sends are log checkpoints, which carry no value and are paid for by a separate key " +
			"that holds only gas. " + policy
	case modeDryRun:
		return "Ask the SPT-Txn enforcement point to authorize a USDC payment on Arc. DRY RUN: on " +
			"ALLOW the pre-sign guard runs but no payment is signed or sent; log checkpoints are " +
			"still published from a separate gas-only key. " + policy
	}
	return "Ask the SPT-Txn enforcement point to authorize and settle a USDC payment on Arc. The " +
		"agent holds no keys; on ALLOW the enforcement point settles REAL USDC through a pre-sign " +
		"guard and returns the transaction link. " + policy
}

// reply is a tool result whose first line states the mode, so what the server
// can do is part of every answer, not something an operator has to vouch for.
func (s *server) reply(text string, isError bool) interface{} {
	return toolText(fmt.Sprintf("[mode: %s; payments: %s; checkpoints: %s]\n%s",
		s.mode, s.payments(), s.checkpoints(), text), isError)
}

func (s *server) toolsList() interface{} {
	if s.toolName() == "" {
		return map[string]interface{}{"tools": []interface{}{}}
	}
	return map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name":        s.toolName(),
				"description": s.toolDescription(),
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"to":          map[string]interface{}{"type": "string", "description": "recipient: a 0x address, or the demo label \"merchant\" or \"attacker\""},
						"amount_usdc": map[string]interface{}{"type": "string", "description": "amount in USDC as a decimal string, at most 6 decimal places, e.g. \"0.5\" (required; a JSON number or an omitted amount is refused, not treated as zero)"},
						"resource":    map[string]interface{}{"type": "string", "description": "what is being paid for, e.g. invoice:42"},
					},
					"required":             []interface{}{"to", "amount_usdc", "resource"},
					"additionalProperties": false,
				},
			},
		},
	}
}

func toolText(text string, isError bool) interface{} {
	return map[string]interface{}{
		"content": []interface{}{map[string]interface{}{"type": "text", "text": text}},
		"isError": isError,
	}
}

// resolveTo maps the demo labels to addresses; anything else must be a 0x
// address. The result is never the agent's raw string.
func (s *server) resolveTo(to string) (evm.Address, error) {
	switch to {
	case "merchant":
		return s.cap.Recipient, nil
	case "attacker":
		return attackerAddress, nil
	}
	return evm.ParseAddress(to)
}

func (s *server) toolsCall(ctx context.Context, params json.RawMessage) interface{} {
	// SPEC-ARC-M3 §3: one reading of the authorized object, or a refusal.
	required := []string{"to", "amount_usdc", "resource"}
	if s.m3 != nil {
		required = append(required, m3Args...)
	}
	tc, err := parseToolCall(params, required)
	if err != nil {
		return s.reply("DENY_VIOLATION: "+err.Error(), true)
	}
	if s.toolName() == "" {
		return s.reply("DENY_UNAVAILABLE: this server has no valid mode and refuses every call", true)
	}
	if tc.Name != s.toolName() {
		return s.reply("unknown tool: "+tc.Name, true)
	}
	var digest intent.Digest
	var paymentID [32]byte
	if s.m3 != nil {
		if digest, paymentID, err = s.m3.precheck(tc); err != nil {
			return s.reply("DENY_VIOLATION: "+err.Error(), true)
		}
	}
	micro, err := amount.ParseMicro(tc.Args["amount_usdc"])
	if err != nil {
		return s.reply("DENY_VIOLATION: "+err.Error(), true)
	}
	to, err := s.resolveTo(tc.Args["to"])
	if err != nil {
		return s.reply("DENY_VIOLATION: recipient: "+err.Error(), true)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return s.reply("DENY_UNAVAILABLE: unable to generate a single-use nonce", true)
	}
	// I5: a call's expiry never exceeds the capability's.
	expiry := s.now().Add(time.Minute)
	if s.cap.ExpiresAt.Before(expiry) {
		expiry = s.cap.ExpiresAt
	}
	call := mcpgate.ToolCall{
		To:       evm.AccountIDBase58(to),
		Asset:    evm.AccountIDBase58(s.cap.Net.USDC),
		Amount:   strconv.FormatUint(micro, 10),
		Resource: tc.Args["resource"],
		Nonce:    nonce,
		Expiry:   expiry,
	}
	r := s.enf.Authorize(call)
	// Count an ALLOW before anything else, so a later failure cannot leave the
	// capability with an authorization it has not counted.
	if r.Allowed() {
		*s.used++
	}
	s.entered = true

	// §6: the decision and the count are persisted before anything acts on
	// them. If they cannot be, nothing is settled; an ALLOW's nonce is already
	// spent, so the agent needs a fresh call, not a retry.
	if err := s.persist(); err != nil {
		_, _ = fmt.Fprintf(s.diag, "EVIDENCE FAILURE: decision not persisted: %v\n", err)
		return s.reply("DENY_UNAVAILABLE: the decision could not be persisted, so nothing was settled", true)
	}
	if !r.Allowed() {
		return s.reply(fmt.Sprintf("REFUSED by the SPT-Txn enforcement point (%s): %s. Nothing was signed. Log entry %s.",
			r.Class, r.Reason, orNone(r.LogEntry)), true)
	}
	// §6a: in evaluate-only mode the decision is the answer, even if a settler
	// were somehow present.
	if s.mode == modeEvaluate {
		return s.reply(fmt.Sprintf("ALLOWED by the SPT-Txn enforcement point (log entry %s). "+
			"Evaluate-only: this server holds no payment key; nothing was signed or sent.", r.LogEntry), false)
	}
	if s.m3 != nil && s.m3.rail == railEIP3009 {
		return s.reply(s.authorizeEIP3009(ctx, r.LogEntry, digest, paymentID, to, micro, expiry))
	}
	if s.settle == nil {
		return s.reply(fmt.Sprintf("AUTHORIZED (log entry %s), but this server has no settler; nothing was signed or sent.", r.LogEntry), true)
	}

	// I1: every field below comes from the authorized call, except Recipient,
	// the approved address, which the settler proves the call names.
	payment := arcpay.Payment{
		Authorization:  r.LogEntry,
		Recipient:      s.cap.Recipient,
		PayToTransport: call.To,
		AssetTransport: call.Asset,
		AmountMicro:    call.Amount,
		NotAfter:       call.Expiry,
	}
	if s.m3 != nil {
		payment.BeforeSign = s.m3.beforeSign(r.LogEntry, digest, paymentID)
	}
	res, err := s.settle(ctx, payment)
	if err != nil {
		_, _ = fmt.Fprintf(s.diag, "settlement after ALLOW %s failed: %v\n", r.LogEntry, err)
		return s.reply(fmt.Sprintf("AUTHORIZED (log entry %s), but settlement did not complete: %s",
			r.LogEntry, firstLine(err.Error())), true)
	}
	if res.TxHash == (common.Hash{}) {
		return s.reply(fmt.Sprintf("AUTHORIZED (log entry %s). DRY RUN: the pre-sign guard passed; nothing was signed or sent.", r.LogEntry), false)
	}
	return s.reply(fmt.Sprintf("AUTHORIZED by the SPT-Txn enforcement point and settled on Arc %s through the pre-sign guard.\n"+
		"  log entry: %s\n  tx: %s%s (block %d)",
		s.cap.Net.Name, r.LogEntry, s.cap.Net.ExplorerTxPrefix, res.TxHash.Hex(), res.Block), false)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

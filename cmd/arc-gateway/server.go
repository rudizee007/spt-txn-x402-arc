//go:build arc

package main

import (
	"bufio"
	"bytes"
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

type server struct {
	cap     capability
	enf     authorizer
	settle  settleFunc
	persist func() error // persist the log and the payment count after every decision (§6)
	onEntry func()       // called after every recorded decision (checkpoints, §5)
	now     func() time.Time
	used    *int // ALLOWs issued under this capability; shared with the policy
	out     io.Writer
	diag    io.Writer
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
	s.out.Write(append(b, '\n'))
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

func (s *server) toolsList() interface{} {
	return map[string]interface{}{
		"tools": []interface{}{
			map[string]interface{}{
				"name": "authorize_payment",
				"description": "Ask the SPT-Txn enforcement point to authorize and settle a USDC payment on Arc. " +
					"It is allowed only if it matches the one capability a human approved: recipient, " +
					"resource, a maximum amount and an expiry. The agent holds no keys; on ALLOW the " +
					"enforcement point settles through a pre-sign guard and returns the transaction link. " +
					"Every decision, allowed or refused, is recorded in a signed transparency log.",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"to":          map[string]interface{}{"type": "string", "description": "recipient: a 0x address, or the demo label \"merchant\" or \"attacker\""},
						"amount_usdc": map[string]interface{}{"type": "number", "description": "amount in USDC, at most 6 decimal places (required; an omitted amount is refused, not treated as zero)"},
						"resource":    map[string]interface{}{"type": "string", "description": "what is being paid for, e.g. invoice:42"},
					},
					"required": []interface{}{"to", "amount_usdc", "resource"},
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
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			To string `json:"to"`
			// json.Number keeps the caller's digits; the pointer separates an
			// absent amount from zero (see spt-txn-pep/amount).
			AmountUSDC *json.Number `json:"amount_usdc"`
			Resource   string       `json:"resource"`
		} `json:"arguments"`
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return toolText("invalid tool arguments", true)
	}
	if p.Name != "authorize_payment" {
		return toolText("unknown tool: "+p.Name, true)
	}
	if p.Arguments.AmountUSDC == nil {
		return toolText("DENY_VIOLATION: amount_usdc is required; an omitted amount is not a zero amount", true)
	}
	micro, err := amount.ParseMicro(string(*p.Arguments.AmountUSDC))
	if err != nil {
		return toolText("DENY_VIOLATION: "+err.Error(), true)
	}
	to, err := s.resolveTo(p.Arguments.To)
	if err != nil {
		return toolText("DENY_VIOLATION: recipient: "+err.Error(), true)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return toolText("DENY_UNAVAILABLE: unable to generate a single-use nonce", true)
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
		Resource: p.Arguments.Resource,
		Nonce:    nonce,
		Expiry:   expiry,
	}
	r := s.enf.Authorize(call)
	// Count an ALLOW before anything else, so a later failure cannot leave the
	// capability with an authorization it has not counted.
	if r.Allowed() {
		*s.used++
	}
	// The checkpoint runs after this call is answered, never before
	// settlement, so it cannot delay a payment toward its expiry.
	if s.onEntry != nil {
		defer s.onEntry()
	}

	// §6: the decision and the count are persisted before anything acts on
	// them. If they cannot be, nothing is settled; an ALLOW's nonce is already
	// spent, so the agent needs a fresh call, not a retry.
	if err := s.persist(); err != nil {
		fmt.Fprintf(s.diag, "EVIDENCE FAILURE: decision not persisted: %v\n", err)
		return toolText("DENY_UNAVAILABLE: the decision could not be persisted, so nothing was settled", true)
	}
	if !r.Allowed() {
		return toolText(fmt.Sprintf("REFUSED by the SPT-Txn enforcement point (%s): %s. Nothing was signed. Log entry %s.",
			r.Class, r.Reason, orNone(r.LogEntry)), true)
	}
	// I1: every field below comes from the authorized call, except Recipient,
	// the approved address, which the settler proves the call names.
	res, err := s.settle(ctx, arcpay.Payment{
		Authorization:  r.LogEntry,
		Recipient:      s.cap.Recipient,
		PayToTransport: call.To,
		AssetTransport: call.Asset,
		AmountMicro:    call.Amount,
		NotAfter:       call.Expiry,
	})
	if err != nil {
		fmt.Fprintf(s.diag, "settlement after ALLOW %s failed: %v\n", r.LogEntry, err)
		return toolText(fmt.Sprintf("AUTHORIZED (log entry %s), but settlement did not complete: %s",
			r.LogEntry, firstLine(err.Error())), true)
	}
	if res.TxHash == (common.Hash{}) {
		return toolText(fmt.Sprintf("AUTHORIZED (log entry %s). DRY RUN: the pre-sign guard passed; nothing was signed or sent.", r.LogEntry), false)
	}
	return toolText(fmt.Sprintf("AUTHORIZED by the SPT-Txn enforcement point and settled on Arc %s through the pre-sign guard.\n"+
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

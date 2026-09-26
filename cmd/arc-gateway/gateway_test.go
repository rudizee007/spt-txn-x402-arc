//go:build arc

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/mcpgate"
	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

var (
	t0        = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	merchant  = evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d")
	testCap   = capability{Net: evm.ArcTestnet(), Recipient: merchant, Resource: "invoice:42", MaxMicro: 1_000_000, MaxPayments: 1, ExpiresAt: t0.Add(time.Hour)}
	errNoPay  = errors.New("test settler refused")
	anyResult = arcpay.Result{Block: 7}
)

// recorder is a settler that records what it was asked to pay.
type recorder struct {
	calls []arcpay.Payment
	err   error
}

func (r *recorder) settle(_ context.Context, p arcpay.Payment) (arcpay.Result, error) {
	r.calls = append(r.calls, p)
	return anyResult, r.err
}

// fixedAuthorizer returns one result and records the call it was given.
type fixedAuthorizer struct {
	res  mcpgate.Result
	seen []mcpgate.ToolCall
}

func (f *fixedAuthorizer) Authorize(c mcpgate.ToolCall) mcpgate.Result {
	f.seen = append(f.seen, c)
	return f.res
}

func realEnforcer(t *testing.T, cp capability, used *int, now func() time.Time) *mcpgate.Enforcer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &mcpgate.Enforcer{
		Scheme: "exact", Network: cp.Net.CAIP2,
		Allowlist: gate.Allowlist{Schemes: map[string]byte{"exact": 1}, Networks: map[string]byte{cp.Net.CAIP2: cp.Net.NetworkTag}},
		Policy: countingPolicy{
			exact: mcpgate.ExactPayment{Asset: evm.AccountIDBase58(cp.Net.USDC), PayTo: evm.AccountIDBase58(cp.Recipient), Resource: cp.Resource, MaxAmount: cp.MaxMicro},
			max:   cp.MaxPayments, used: used,
		},
		Spend: gate.NewMemSpendLog(), Log: translog.NewLog(pub), RKey: priv, Now: now,
		Logf: func(string, ...any) {},
	}
}

func newTestServer(enf authorizer, settle settleFunc, used *int) *server {
	return &server{
		cap: testCap, enf: enf, settle: settle,
		saveLog: func() error { return nil },
		now:     func() time.Time { return t0 }, used: used,
		out: io.Discard, diag: io.Discard,
	}
}

func call(s *server, to, amount, resource string) (string, bool) {
	args := map[string]interface{}{"to": to, "resource": resource}
	if amount != "" {
		args["amount_usdc"] = json.Number(amount)
	}
	params, _ := json.Marshal(map[string]interface{}{"name": "authorize_payment", "arguments": args})
	res := s.toolsCall(context.Background(), params).(map[string]interface{})
	text := res["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	return text, res["isError"].(bool)
}

// §8.1 / I2: a DENY never reaches settlement, and neither does an ALLOW with
// no log locator.
func TestNoAllowNoSettlement(t *testing.T) {
	for name, res := range map[string]mcpgate.Result{
		"deny violation":        {Class: gate.DenyViolation, Reason: "recipient not authorized", LogEntry: "1:ab"},
		"deny unavailable":      {Class: gate.DenyUnavailable, Reason: "down"},
		"allow without locator": {Class: gate.Allow, Reason: "ok"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			used := 0
			text, isErr := call(newTestServer(&fixedAuthorizer{res: res}, rec.settle, &used), "merchant", "0.5", "invoice:42")
			if !isErr || len(rec.calls) != 0 {
				t.Fatalf("settlement ran (%d calls) or call succeeded: %s", len(rec.calls), text)
			}
		})
	}
}

// §8.2 / I1: the settler is handed exactly the authorized call's recipient,
// asset and amount, and the approved recipient.
func TestSettlerReceivesTheAuthorizedCall(t *testing.T) {
	rec := &recorder{}
	used := 0
	s := newTestServer(realEnforcer(t, testCap, &used, func() time.Time { return t0 }), rec.settle, &used)
	if text, isErr := call(s, "merchant", "0.5", "invoice:42"); isErr {
		t.Fatalf("in-scope payment refused: %s", text)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("settler called %d times", len(rec.calls))
	}
	p := rec.calls[0]
	if p.Authorization == "" || p.AmountMicro != "500000" || p.Recipient != merchant ||
		p.PayToTransport != evm.AccountIDBase58(merchant) || p.AssetTransport != evm.AccountIDBase58(testCap.Net.USDC) {
		t.Fatalf("settler got %+v", p)
	}
}

// §8.3 / I3, settler half: with an enforcement point that allows everything,
// the settler still refuses a payment to anyone but the approved recipient,
// before touching a key or an endpoint.
func TestSettlerRefusesOnItsOwn(t *testing.T) {
	allowAll := &fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, Reason: "ok", LogEntry: "1:ab"}}
	var got error
	settle := func(ctx context.Context, p arcpay.Payment) (arcpay.Result, error) {
		r, err := arcpay.Settle(ctx, arcpay.Config{Net: testCap.Net, MaxFeeMicro: 1}, p)
		got = err
		return r, err
	}
	used := 0
	text, isErr := call(newTestServer(allowAll, settle, &used), "attacker", "0.5", "invoice:42")
	if !isErr || !errors.Is(got, arcpay.ErrViolation) || !errors.Is(got, evm.ErrTransportMismatch) {
		t.Fatalf("an allow-all enforcement point got a payment to the attacker past the settler: err=%v text=%s", got, text)
	}
}

// §8.4 / I3, enforcement half: with a settler that would pay anything, the
// enforcement point still refuses every call outside the capability.
func TestEnforcementRefusesOnItsOwn(t *testing.T) {
	cases := [][3]string{
		{"attacker", "0.5", "invoice:42"},
		{"merchant", "2", "invoice:42"},
		{"merchant", "0.5", "invoice:99"},
		{"0x5555555555555555555555555555555555555555", "0.5", "invoice:42"},
	}
	for _, c := range cases {
		rec := &recorder{}
		used := 0
		s := newTestServer(realEnforcer(t, testCap, &used, func() time.Time { return t0 }), rec.settle, &used)
		if text, isErr := call(s, c[0], c[1], c[2]); !isErr || len(rec.calls) != 0 {
			t.Fatalf("%v reached settlement: %s", c, text)
		}
	}
}

// §8.5 / I5: an expired capability refuses every call, and no call's expiry
// is later than the capability's.
func TestCapabilityExpiry(t *testing.T) {
	rec := &recorder{}
	used := 0
	late := func() time.Time { return testCap.ExpiresAt.Add(time.Second) }
	s := newTestServer(realEnforcer(t, testCap, &used, late), rec.settle, &used)
	s.now = late
	if text, isErr := call(s, "merchant", "0.5", "invoice:42"); !isErr || len(rec.calls) != 0 {
		t.Fatalf("a call after the capability expired was allowed: %s", text)
	}
	fa := &fixedAuthorizer{res: mcpgate.Result{Class: gate.DenyViolation}}
	s2 := newTestServer(fa, rec.settle, &used)
	s2.now = func() time.Time { return testCap.ExpiresAt.Add(-10 * time.Second) }
	call(s2, "merchant", "0.5", "invoice:42")
	if len(fa.seen) != 1 || fa.seen[0].Expiry.After(testCap.ExpiresAt) {
		t.Fatalf("a call's expiry exceeded the capability's: %+v", fa.seen)
	}
}

// max_payments: once used up, further calls are refused by the enforcement
// point (a recorded DENY), not dropped by the server.
func TestCapabilityPaymentCount(t *testing.T) {
	rec := &recorder{}
	used := 0
	enf := realEnforcer(t, testCap, &used, func() time.Time { return t0 })
	s := newTestServer(enf, rec.settle, &used)
	if _, isErr := call(s, "merchant", "0.5", "invoice:42"); isErr {
		t.Fatal("first payment refused")
	}
	text, isErr := call(s, "merchant", "0.5", "invoice:42")
	if !isErr || len(rec.calls) != 1 || !strings.Contains(text, "used up") {
		t.Fatalf("second payment under a one-payment capability: %s", text)
	}
	if enf.Log.Len() != 2 {
		t.Fatalf("the refusal was not recorded: log has %d entries", enf.Log.Len())
	}
}

// §8.7 / §6: if the decision cannot be persisted, nothing is settled.
func TestLogSaveFailurePreventsSettlement(t *testing.T) {
	rec := &recorder{}
	used := 0
	s := newTestServer(realEnforcer(t, testCap, &used, func() time.Time { return t0 }), rec.settle, &used)
	s.saveLog = func() error { return errors.New("disk full") }
	if text, isErr := call(s, "merchant", "0.5", "invoice:42"); !isErr || len(rec.calls) != 0 {
		t.Fatalf("settlement ran although the decision was not persisted: %s", text)
	}
}

func TestAmountRules(t *testing.T) {
	rec := &recorder{}
	used := 0
	s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "1:ab"}}, rec.settle, &used)
	for _, a := range []string{"", "0", "-1", "1e6", "0.0000001", "01"} {
		if text, isErr := call(s, "merchant", a, "invoice:42"); !isErr || len(rec.calls) != 0 {
			t.Fatalf("amount %q accepted: %s", a, text)
		}
	}
}

// §8.8: startup refuses a malformed capability and a shared key.
func TestParseCapability(t *testing.T) {
	good := `{"network":"testnet","recipient":"0x79A34Cc563f848f626038Ff312CCEBfb5374971d","resource":"invoice:42","max_amount_micro":1000000,"expires_at":"2026-10-01T13:00:00Z"}`
	cp, err := parseCapability(strings.NewReader(good), t0)
	if err != nil || cp.MaxPayments != 1 || cp.Recipient != merchant || cp.Net.Name != "testnet" {
		t.Fatalf("good capability: %+v, %v", cp, err)
	}
	for name, body := range map[string]string{
		"unknown field":  strings.Replace(good, `"resource"`, `"extra":1,"resource"`, 1),
		"trailing data":  good + `{}`,
		"bad network":    strings.Replace(good, `"testnet"`, `"Mainnet"`, 1),
		"zero recipient": strings.Replace(good, "0x79A34Cc563f848f626038Ff312CCEBfb5374971d", "0x0000000000000000000000000000000000000000", 1),
		"no resource":    strings.Replace(good, `"invoice:42"`, `""`, 1),
		"zero ceiling":   strings.Replace(good, `1000000`, `0`, 1),
		"no ceiling":     strings.Replace(good, `"max_amount_micro":1000000,`, ``, 1),
		"expired":        strings.Replace(good, "2026-10-01T13:00:00Z", "2026-10-01T11:00:00Z", 1),
		"no expiry":      strings.Replace(good, `,"expires_at":"2026-10-01T13:00:00Z"`, ``, 1),
		"zero payments":  strings.Replace(good, `"resource"`, `"max_payments":0,"resource"`, 1),
		"not json":       `nope`,
	} {
		if _, err := parseCapability(strings.NewReader(body), t0); !errors.Is(err, errCapability) {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
	}
	if err := distinctKeys(common.Address{1}, common.Address{1}); !errors.Is(err, arcpay.ErrViolation) {
		t.Fatal("a checkpoint key equal to the payment key was accepted")
	}
	if err := distinctKeys(common.Address{1}, common.Address{2}); err != nil {
		t.Fatal(err)
	}
}

// The protocol loop answers requests and stays silent for notifications.
func TestServeProtocol(t *testing.T) {
	var out bytes.Buffer
	used := 0
	s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.DenyViolation}}, (&recorder{}).settle, &used)
	s.out = &out
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"nope"}` + "\n")
	s.serve(context.Background(), in)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "2025-06-18") || !strings.Contains(lines[1], "authorize_payment") || !strings.Contains(lines[2], "-32601") {
		t.Fatalf("protocol replies: %q", lines)
	}
}

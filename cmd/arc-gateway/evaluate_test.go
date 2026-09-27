//go:build arc

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/mcpgate"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// §6a: the mode is fixed by the flags, and evaluate-only never runs with a
// payment key.
func TestResolveMode(t *testing.T) {
	cases := []struct {
		eval, dry bool
		key       string
		extra     []string
		want      string
		wantErr   error
	}{
		{false, false, "pay.key", nil, modeLive, nil},
		{false, true, "pay.key", nil, modeDryRun, nil},
		{true, false, "", nil, modeEvaluate, nil},
		{true, false, "pay.key", nil, "", arcpay.ErrViolation},
		{true, true, "", nil, "", arcpay.ErrViolation},
		{false, false, "", nil, "", arcpay.ErrUnavailable},
		{false, true, "", nil, "", arcpay.ErrUnavailable},
		// A stray argument ends flag parsing; -evaluate-only after it would be lost.
		{false, false, "pay.key", []string{"stray", "-evaluate-only"}, "", arcpay.ErrViolation},
		{true, false, "", []string{"stray"}, "", arcpay.ErrViolation},
	}
	for _, c := range cases {
		got, err := resolveMode(c.eval, c.dry, c.key, c.extra)
		errOK := errors.Is(err, c.wantErr)
		if c.wantErr == nil {
			errOK = err == nil
		}
		if got != c.want || !errOK {
			t.Fatalf("resolveMode(%v, %v, %q) = %q, %v; want %q, %v", c.eval, c.dry, c.key, got, err, c.want, c.wantErr)
		}
	}
}

func evaluateServer(t *testing.T, settle settleFunc) (*server, *int) {
	t.Helper()
	used := 0
	s := newTestServer(realEnforcer(t, testCap, &used, func() time.Time { return t0 }), settle, &used)
	s.mode = modeEvaluate
	return s, &used
}

// The evaluate-only server offers only evaluate_payment, and says it cannot
// sign; authorize_payment is an unknown tool there.
func TestEvaluateOnlyOffersOnlyTheSideEffectFreeTool(t *testing.T) {
	s, _ := evaluateServer(t, nil)
	list, _ := json.Marshal(s.toolsList())
	if !bytes.Contains(list, []byte(`"evaluate_payment"`)) || bytes.Contains(list, []byte(`"authorize_payment"`)) ||
		!bytes.Contains(list, []byte("cannot sign or send any payment")) {
		t.Fatalf("evaluate-only tools/list: %s", list)
	}
	params, _ := json.Marshal(map[string]interface{}{"name": "authorize_payment",
		"arguments": map[string]interface{}{"to": "merchant", "amount_usdc": json.Number("0.5"), "resource": "invoice:42"}})
	res := s.toolsCall(context.Background(), params).(map[string]interface{})
	text := res["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !res["isError"].(bool) || !strings.Contains(text, "unknown tool") {
		t.Fatalf("authorize_payment on an evaluate-only server: %s", text)
	}
	live := newTestServer(&fixedAuthorizer{}, (&recorder{}).settle, new(int))
	llist, _ := json.Marshal(live.toolsList())
	if bytes.Contains(llist, []byte(`"evaluate_payment"`)) || !bytes.Contains(llist, []byte(`"authorize_payment"`)) {
		t.Fatalf("live tools/list: %s", llist)
	}
}

// An ALLOW in evaluate-only mode is answered, recorded and counted, and never
// settled, even if a settler were somehow present.
func TestEvaluateOnlyNeverSettles(t *testing.T) {
	rec := &recorder{}
	s, used := evaluateServer(t, rec.settle)
	text, isErr := call(s, "merchant", "0.5", "invoice:42")
	if isErr || len(rec.calls) != 0 || !strings.Contains(text, "nothing was signed or sent") {
		t.Fatalf("evaluate-only ALLOW: settled %d times, reply %q", len(rec.calls), text)
	}
	if *used != 1 {
		t.Fatalf("an evaluate-only ALLOW was not counted: used=%d", *used)
	}
	s2, _ := evaluateServer(t, nil)
	if text, isErr := call(s2, "merchant", "0.5", "invoice:42"); isErr {
		t.Fatalf("evaluate-only with no settler: %s", text)
	}
}

// Refusals in evaluate-only mode are the same decisions as in live mode.
func TestEvaluateOnlyRefusesLikeLive(t *testing.T) {
	s, _ := evaluateServer(t, nil)
	for _, c := range [][3]string{{"attacker", "0.5", "invoice:42"}, {"merchant", "2", "invoice:42"}, {"merchant", "0.5", "invoice:99"}} {
		text, isErr := call(s, c[0], c[1], c[2])
		if !isErr || !strings.Contains(text, "REFUSED") || !strings.Contains(text, "DENY_VIOLATION") {
			t.Fatalf("%v in evaluate-only mode: %s", c, text)
		}
	}
}

// Every reply states the mode and whether anything can be broadcast.
func TestEveryReplyStatesTheMode(t *testing.T) {
	for mode, want := range map[string]string{
		modeLive:     "[mode: live; payments: settled on ALLOW; checkpoints: off]",
		modeDryRun:   "[mode: dry-run; payments: guard only, nothing signed; checkpoints: off]",
		modeEvaluate: "[mode: evaluate-only; payments: no payment key, none can be sent; checkpoints: off]",
	} {
		used := 0
		s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.DenyViolation, LogEntry: "0:ab"}}, (&recorder{}).settle, &used)
		s.mode = mode
		text, _ := call(s, "merchant", "0.5", "invoice:42")
		if !strings.HasPrefix(text, want) {
			t.Fatalf("%s reply does not start with %q: %q", mode, want, text)
		}
	}
}

// The prefix says checkpoints are on when they are.
func TestReplyStatesCheckpoints(t *testing.T) {
	s, _ := evaluateServer(t, nil)
	s.onEntry = func() {}
	text, _ := call(s, "attacker", "0.5", "invoice:42")
	if !strings.HasPrefix(text, "[mode: evaluate-only; payments: no payment key, none can be sent; checkpoints: on, from a separate gas-only key]") {
		t.Fatalf("prefix with checkpoints: %q", text)
	}
}

func callNamed(s *server, name string) (string, bool) {
	params, _ := json.Marshal(map[string]interface{}{"name": name,
		"arguments": map[string]interface{}{"to": "merchant", "amount_usdc": json.Number("0.5"), "resource": "invoice:42"}})
	res := s.toolsCall(context.Background(), params).(map[string]interface{})
	return res["content"].([]interface{})[0].(map[string]interface{})["text"].(string), res["isError"].(bool)
}

// A live or dry-run server never answers evaluate_payment: a host that treats
// that name as side-effect free must not reach a settler through it.
func TestSettlingServersRefuseEvaluatePayment(t *testing.T) {
	for _, mode := range []string{modeLive, modeDryRun} {
		rec := &recorder{}
		used := 0
		s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "0:ab"}}, rec.settle, &used)
		s.mode = mode
		text, isErr := callNamed(s, "evaluate_payment")
		if !isErr || !strings.Contains(text, "unknown tool") || len(rec.calls) != 0 {
			t.Fatalf("%s server answered evaluate_payment (settled %d): %s", mode, len(rec.calls), text)
		}
	}
}

// A server whose mode is not one of the three offers no tool and refuses every
// call, so a wiring mistake cannot produce a settling server that describes
// itself as something else.
func TestUnknownModeRefusesEverything(t *testing.T) {
	for _, mode := range []string{"", "LIVE", "evaluate"} {
		rec := &recorder{}
		used := 0
		s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "0:ab"}}, rec.settle, &used)
		s.mode = mode
		list, _ := json.Marshal(s.toolsList())
		if !bytes.Equal(list, []byte(`{"tools":[]}`)) {
			t.Fatalf("mode %q lists tools: %s", mode, list)
		}
		for _, name := range []string{"authorize_payment", "evaluate_payment", ""} {
			if text, isErr := callNamed(s, name); !isErr || len(rec.calls) != 0 || !strings.Contains(text, "no valid mode") {
				t.Fatalf("mode %q, tool %q: settled %d, %s", mode, name, len(rec.calls), text)
			}
		}
	}
}

// A live server built without a settler reports an error, never an ALLOW that
// reads like an evaluation.
func TestLiveWithoutSettlerIsAnError(t *testing.T) {
	used := 0
	s := newTestServer(&fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "0:ab"}}, nil, &used)
	text, isErr := call(s, "merchant", "0.5", "invoice:42")
	if !isErr || !strings.Contains(text, "no settler") || strings.Contains(text, "Evaluate-only") {
		t.Fatalf("live server without a settler: %s", text)
	}
}

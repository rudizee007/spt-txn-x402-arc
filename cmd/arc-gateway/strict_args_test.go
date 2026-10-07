//go:build arc

package main

import (
	"context"
	"testing"

	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/mcpgate"
)

// SPEC-ARC-M3 §3: the enforcement point binds the exact argument object; the
// gateway must read that object in exactly one way or refuse it. Each case below
// is an object the enforcement point can authorize as a whole while a lenient
// decoder reads a different, or a defaulted, payment out of it.
//
// The authorizer here allows everything, so the only control under test is the
// gateway's own reading of the arguments: a case that reaches the settler is a
// case the gateway accepted.
func TestToolArgumentsAreReadInExactlyOneWay(t *testing.T) {
	cases := []struct {
		name string
		args string
	}{
		{"mis-cased duplicate of the recipient", `{"to":"merchant","To":"attacker","amount_usdc":"0.5","resource":"invoice:42"}`},
		{"mis-cased duplicate of the amount", `{"to":"merchant","amount_usdc":"0.5","Amount_USDC":"0.9","resource":"invoice:42"}`},
		{"exact duplicate of the amount", `{"to":"merchant","amount_usdc":"0.5","amount_usdc":"0.9","resource":"invoice:42"}`},
		{"exact duplicate of the recipient", `{"to":"attacker","to":"merchant","amount_usdc":"0.5","resource":"invoice:42"}`},
		{"unknown member", `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42","memo":"read by nobody"}`},
		{"mis-cased member only", `{"TO":"merchant","amount_usdc":"0.5","resource":"invoice:42"}`},
		{"amount as a JSON number, not a decimal string", `{"to":"merchant","amount_usdc":1,"resource":"invoice:42"}`},
		{"required member absent", `{"to":"merchant","amount_usdc":"0.5"}`},
		{"recipient as null", `{"to":null,"amount_usdc":"0.5","resource":"invoice:42"}`},
		{"arguments not an object", `["merchant","0.5","invoice:42"]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{}
			used := 0
			auth := &fixedAuthorizer{res: mcpgate.Result{Class: gate.Allow, LogEntry: "1:ab"}}
			s := newTestServer(auth, rec.settle, &used)
			params := []byte(`{"name":"` + s.toolName() + `","arguments":` + c.args + `}`)
			res := s.toolsCall(context.Background(), params).(map[string]interface{})
			text := res["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
			isErr := res["isError"].(bool)
			if !isErr || len(rec.calls) != 0 {
				read := "nothing"
				if len(auth.seen) > 0 {
					c := auth.seen[0]
					read = "to=" + c.To + " amount=" + c.Amount + " resource=" + c.Resource
				}
				t.Fatalf("accepted %s\n  gateway read: %s\n  reply: %s", c.args, read, firstLine(text))
			}
		})
	}
}

//go:build arc

package main

import (
	"errors"
	"testing"
)

var reqArgs = []string{"to", "amount_usdc", "resource"}

func TestParseToolCallAcceptsTheExactShape(t *testing.T) {
	params := `{"name":"authorize_payment","arguments":{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42"},"_meta":{"progressToken":1}}`
	tc, err := parseToolCall([]byte(params), reqArgs)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Name != "authorize_payment" || tc.Args["to"] != "merchant" || tc.Args["amount_usdc"] != "0.5" || tc.Args["resource"] != "invoice:42" {
		t.Fatalf("parsed %+v", tc)
	}
	if string(tc.RawArguments) != `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42"}` {
		t.Fatalf("raw arguments not kept as received: %s", tc.RawArguments)
	}
}

// The params object is held to the same rules as the arguments: a second
// "arguments" member is exactly the ambiguity §3 closes, one level up.
func TestParseToolCallRefusesAmbiguousParams(t *testing.T) {
	good := `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42"}`
	for name, params := range map[string]string{
		"duplicate arguments":    `{"name":"authorize_payment","arguments":` + good + `,"arguments":{"to":"attacker","amount_usdc":"0.5","resource":"invoice:42"}}`,
		"duplicate name":         `{"name":"evaluate_payment","name":"authorize_payment","arguments":` + good + `}`,
		"mis-cased arguments":    `{"name":"authorize_payment","Arguments":` + good + `}`,
		"unknown params member":  `{"name":"authorize_payment","arguments":` + good + `,"extra":1}`,
		"name not a string":      `{"name":["authorize_payment"],"arguments":` + good + `}`,
		"name absent":            `{"arguments":` + good + `}`,
		"arguments absent":       `{"name":"authorize_payment"}`,
		"data after the object":  `{"name":"authorize_payment","arguments":` + good + `}{}`,
		"params not an object":   `"authorize_payment"`,
		"truncated":              `{"name":"authorize_payment","arguments":{"to":"merchant"`,
		"empty":                  ``,
		"argument value object":  `{"name":"authorize_payment","arguments":{"to":{"a":1},"amount_usdc":"0.5","resource":"invoice:42"}}`,
		"argument value boolean": `{"name":"authorize_payment","arguments":{"to":"merchant","amount_usdc":"0.5","resource":true}}`,
	} {
		if _, err := parseToolCall([]byte(params), reqArgs); !errors.Is(err, errArgs) {
			t.Errorf("%s: accepted (err=%v)", name, err)
		}
	}
}

//go:build arc

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SPEC-ARC-M3 §3: the enforcement point authorizes the exact argument object of
// a tools/call. The gateway therefore reads that object in exactly one way, or
// refuses it. encoding/json does not meet that bar: it matches member names
// case-insensitively, keeps the last of duplicate members, ignores unknown
// members and accepts a number where a string is meant. Each of those lets one
// authorized object carry a payment the authorization did not describe.
//
// The rules here: params and arguments are JSON objects; member names match
// exactly; no member appears twice; no member is unknown; every required
// argument is present; every argument value is a JSON string (amounts are
// decimal strings, never numbers), except the arguments a caller names as
// objects, whose value must be a JSON object; nothing follows the object.
//
// An object-valued argument is not read here beyond its top level. It stays in
// RawArguments, so the intent digest covers it through the same canonicalizer
// as every other argument (and that canonicalizer refuses a duplicate member at
// any depth); its meaning is validated by the rail that uses it.

// errArgs is the single class of refusal; the message says which rule failed.
var errArgs = errors.New("invalid tool arguments")

// paramsMembers is the exact set of tools/call params members. _meta may carry
// entries the enforcement point left in place; the gateway reads none of them.
var paramsMembers = map[string]bool{"name": true, "arguments": true, "_meta": true}

// toolCall is a strictly parsed tools/call.
type toolCall struct {
	Name string
	// RawArguments is the arguments object exactly as received. The intent digest
	// is computed over it, canonicalized, never over these bytes directly.
	RawArguments json.RawMessage
	Args         map[string]string
	// Objects holds the object-valued arguments, as received.
	Objects map[string]json.RawMessage
}

// parseToolCall parses params strictly and requires arguments to hold exactly
// the members in required, each a JSON string, and the members in objects, each
// a JSON object.
func parseToolCall(params []byte, required, objects []string) (toolCall, error) {
	var tc toolCall
	members, err := strictObject(params)
	if err != nil {
		return tc, fmt.Errorf("%w: params: %v", errArgs, err)
	}
	for k := range members {
		if !paramsMembers[k] {
			return tc, fmt.Errorf("%w: params: unknown member %q", errArgs, k)
		}
	}
	nameRaw, ok := members["name"]
	if !ok {
		return tc, fmt.Errorf("%w: params: name is required", errArgs)
	}
	if err := json.Unmarshal(nameRaw, &tc.Name); err != nil || !isJSONString(nameRaw) {
		return tc, fmt.Errorf("%w: params: name must be a string", errArgs)
	}
	argsRaw, ok := members["arguments"]
	if !ok {
		return tc, fmt.Errorf("%w: arguments are required", errArgs)
	}
	argMembers, err := strictObject(argsRaw)
	if err != nil {
		return tc, fmt.Errorf("%w: arguments: %v", errArgs, err)
	}
	want := make(map[string]bool, len(required))
	for _, r := range required {
		want[r] = true
	}
	wantObj := make(map[string]bool, len(objects))
	for _, o := range objects {
		wantObj[o] = true
	}
	tc.Args = make(map[string]string, len(argMembers))
	tc.Objects = make(map[string]json.RawMessage, len(objects))
	for k, v := range argMembers {
		if wantObj[k] {
			if _, err := strictObject(v); err != nil {
				return tc, fmt.Errorf("%w: arguments: %q must be a JSON object: %v", errArgs, k, err)
			}
			tc.Objects[k] = append(json.RawMessage(nil), v...)
			continue
		}
		if !want[k] {
			return tc, fmt.Errorf("%w: arguments: unknown member %q", errArgs, k)
		}
		if !isJSONString(v) {
			return tc, fmt.Errorf("%w: arguments: %q must be a JSON string", errArgs, k)
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return tc, fmt.Errorf("%w: arguments: %q: %v", errArgs, k, err)
		}
		tc.Args[k] = s
	}
	for _, r := range required {
		if _, ok := tc.Args[r]; !ok {
			return tc, fmt.Errorf("%w: arguments: %q is required", errArgs, r)
		}
	}
	for _, o := range objects {
		if _, ok := tc.Objects[o]; !ok {
			return tc, fmt.Errorf("%w: arguments: %q is required", errArgs, o)
		}
	}
	tc.RawArguments = append(json.RawMessage(nil), argsRaw...)
	return tc, nil
}

// strictObject returns the members of one JSON object, refusing a duplicate
// member name and anything after the object. Member values are returned raw.
func strictObject(b []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("member name is not a string")
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate member %q", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return out, nil
}

func isJSONString(v json.RawMessage) bool {
	v = bytes.TrimSpace(v)
	return len(v) >= 2 && v[0] == '"'
}

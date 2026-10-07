package intent

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type referenceVectors struct {
	JCS []struct {
		Name      string `json:"name"`
		Input     string `json:"input_b64"`
		Canonical string `json:"canonical_b64"`
		Refused   bool   `json:"refused"`
	} `json:"jcs"`
	Intent []struct {
		Name      string  `json:"name"`
		Tool      string  `json:"tool"`
		Target    string  `json:"target"`
		Arguments *string `json:"arguments_b64"`
		Digest    string  `json:"digest"`
		Refused   bool    `json:"refused"`
	} `json:"intent"`
}

func loadReference(t *testing.T) referenceVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/reference-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v referenceVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.JCS) < 300 || len(v.Intent) < 10 {
		t.Fatalf("vector file too small: %d jcs, %d intent", len(v.JCS), len(v.Intent))
	}
	return v
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SPEC-ARC-M3 §3 / O-5: byte-for-byte agreement with the reference
// canonicalizer, on every vector, including every refusal.
func TestCanonicalizeMatchesTheReference(t *testing.T) {
	v := loadReference(t)
	accepted, refused := 0, 0
	for _, c := range v.JCS {
		in := mustB64(t, c.Input)
		got, err := Canonicalize(in)
		if c.Refused {
			refused++
			if err == nil {
				t.Errorf("%s: reference refuses %q, this accepts it as %q", c.Name, in, got)
			}
			continue
		}
		accepted++
		if err != nil {
			t.Errorf("%s: reference accepts %q, this refuses: %v", c.Name, in, err)
			continue
		}
		if want := mustB64(t, c.Canonical); !bytes.Equal(got, want) {
			t.Errorf("%s:\n  input %q\n  got   %q\n  want  %q", c.Name, in, got, want)
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("vectors must exercise both outcomes: %d accepted, %d refused", accepted, refused)
	}
}

func TestComputeMatchesTheReference(t *testing.T) {
	v := loadReference(t)
	for _, c := range v.Intent {
		var args []byte
		if c.Arguments != nil {
			args = mustB64(t, *c.Arguments)
		}
		d, err := Compute(c.Tool, args, c.Target)
		if c.Refused {
			if err == nil || !errors.Is(err, ErrIntent) {
				t.Errorf("%s: reference refuses, this gives %s (err=%v)", c.Name, d, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if d.String() != c.Digest {
			t.Errorf("%s: digest %s, reference %s", c.Name, d, c.Digest)
		}
	}
}

// The gateway's invariant: the digest depends on the arguments' value, not on
// the bytes they arrived as. Re-encoding by the enforcement point must not move
// it; a change of value must.
func TestDigestFollowsValueNotBytes(t *testing.T) {
	a, err := Compute("authorize_payment", []byte(`{"to":"merchant","resource":"a<b>&c"}`), "srv")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compute("authorize_payment", []byte(` { "resource" : "a\u003cb\u003e\u0026c" , "to":"merchant" } `), "srv")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("re-encoding the same value changed the digest")
	}
	for _, other := range [][3]string{
		{"authorize_payment", `{"to":"attacker","resource":"a<b>&c"}`, "srv"},
		{"evaluate_payment", `{"to":"merchant","resource":"a<b>&c"}`, "srv"},
		{"authorize_payment", `{"to":"merchant","resource":"a<b>&c"}`, "srv2"},
	} {
		c, err := Compute(other[0], []byte(other[1]), other[2])
		if err != nil || c == a {
			t.Fatalf("a different tool, argument or target gave the same digest: %v", other)
		}
	}
}

func TestEIP3009NonceKnownAnswers(t *testing.T) {
	b, err := os.ReadFile("testdata/eip3009-nonce-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Tag     string `json:"tag"`
		Vectors []struct {
			DigestHex string `json:"intent_digest_hex"`
			Digest    string `json:"intent_digest"`
			Preimage  string `json:"preimage_hex"`
			Nonce     string `json:"nonce_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Tag != EIP3009NonceTag || len(EIP3009NonceTag) != 24 || len(f.Vectors) < 3 {
		t.Fatalf("vector file does not match the specified tag or is too small")
	}
	for _, v := range f.Vectors {
		d, err := ParseDigest(v.Digest)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(d[:]) != v.DigestHex {
			t.Fatalf("digest decoding: %x, want %s", d, v.DigestHex)
		}
		pre := append(append([]byte(EIP3009NonceTag), 0x00), d[:]...)
		if len(pre) != 57 || hex.EncodeToString(pre) != v.Preimage {
			t.Fatalf("preimage %x, want %s", pre, v.Preimage)
		}
		n := EIP3009Nonce(d)
		if hex.EncodeToString(n[:]) != v.Nonce {
			t.Fatalf("nonce for %s: %x, want %s", v.Digest, n, v.Nonce)
		}
		if n == [32]byte(d) {
			t.Fatal("the nonce equals the digest it was derived from (M8)")
		}
	}
}

func TestParseDigestAcceptsOnlyCanonicalUnpaddedBase64url(t *testing.T) {
	good := strings.Repeat("A", 43) // 32 zero bytes
	if _, err := ParseDigest(good); err != nil {
		t.Fatalf("canonical digest refused: %v", err)
	}
	for name, s := range map[string]string{
		"padded":                good + "=",
		"standard alphabet":     strings.Repeat("A", 42) + "+",
		"non-canonical bits":    strings.Repeat("A", 42) + "B", // last char carries unused set bits
		"31 bytes":              strings.Repeat("A", 42),
		"33 bytes":              strings.Repeat("A", 44),
		"empty":                 "",
		"whitespace":            good[:20] + " " + good[20:],
		"trailing newline":      good + "\n",
		"standard with padding": base64.StdEncoding.EncodeToString(make([]byte, 32)),
	} {
		if _, err := ParseDigest(s); !errors.Is(err, ErrIntent) {
			t.Errorf("%s: %q accepted", name, s)
		}
	}
}

// Canonical output is a fixed point: canonicalizing it again changes nothing.
func FuzzCanonicalizeIsIdempotent(f *testing.F) {
	for _, s := range []string{`{}`, `{"b":[1," "],"a":{"":1,"😀":2}}`, `"\u0000/\\"`, `[true,null,-9007199254740991]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := Canonicalize(in)
		if err != nil {
			return
		}
		c2, err := Canonicalize(c)
		if err != nil || !bytes.Equal(c, c2) {
			t.Fatalf("not a fixed point: %q -> %q (%v)", c, c2, err)
		}
	})
}

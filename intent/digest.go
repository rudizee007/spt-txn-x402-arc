package intent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Domain tags. Each is written as its ASCII bytes followed by one 0x00.
const (
	// IntentTag is the reference intent-digest tag (DELEGATION-INTENT-MCP §2.1).
	IntentTag = "spt-txn-intent-v1"
	// EIP3009NonceTag separates the EIP-3009 nonce from the digest it is derived
	// from (SPEC-ARC-M3 §4.1.4, invariant M8).
	EIP3009NonceTag = "spt-txn-eip3009-nonce-v1"
)

// ErrIntent is the class of every refusal to compute a digest.
var ErrIntent = errors.New("intent: cannot compute the intent digest")

// Digest is a raw 32-byte intent digest.
type Digest [32]byte

// String is the digest's wire form: unpadded base64url.
func (d Digest) String() string { return base64.RawURLEncoding.EncodeToString(d[:]) }

// Compute returns the intent digest of a tools/call, exactly as the reference
// enforcement point computes it:
//
//	SHA-256( "spt-txn-intent-v1" || 0x00 || JCS({"tool":tool,"params":params,"target":target}) )
//
// rawArguments is the arguments object as received, before any decoding; an
// absent arguments member is passed as nil and binds as {}. tool and target
// must be non-empty. The arguments must be a JSON object in the accepted subset.
func Compute(tool string, rawArguments []byte, target string) (Digest, error) {
	if tool == "" {
		return Digest{}, fmt.Errorf("%w: empty tool", ErrIntent)
	}
	if target == "" {
		return Digest{}, fmt.Errorf("%w: empty target", ErrIntent)
	}
	params := []byte("{}")
	if len(rawArguments) > 0 {
		c, err := Canonicalize(rawArguments)
		if err != nil {
			return Digest{}, fmt.Errorf("%w: arguments: %v", ErrIntent, err)
		}
		if len(c) == 0 || c[0] != '{' {
			return Digest{}, fmt.Errorf("%w: arguments must be a JSON object", ErrIntent)
		}
		params = c
	}
	toolJSON, err := canonicalString(tool)
	if err != nil {
		return Digest{}, fmt.Errorf("%w: tool: %v", ErrIntent, err)
	}
	targetJSON, err := canonicalString(target)
	if err != nil {
		return Digest{}, fmt.Errorf("%w: target: %v", ErrIntent, err)
	}
	// The three keys sort as params < target < tool, in UTF-16 and in bytes.
	var obj bytes.Buffer
	obj.WriteString(`{"params":`)
	obj.Write(params)
	obj.WriteString(`,"target":`)
	obj.Write(targetJSON)
	obj.WriteString(`,"tool":`)
	obj.Write(toolJSON)
	obj.WriteByte('}')

	h := sha256.New()
	h.Write([]byte(IntentTag))
	h.Write([]byte{0x00})
	h.Write(obj.Bytes())
	var d Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}

func canonicalString(s string) ([]byte, error) {
	if err := checkString(s); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writeString(&b, s)
	return b.Bytes(), nil
}

// ParseDigest decodes a digest's wire form. Only canonical unpadded base64url
// of exactly 32 bytes is accepted; padded, standard-alphabet and non-canonical
// encodings are refused, not normalized.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	// The decoder skips '\r' and '\n'; check length and alphabet first, so the
	// only accepted form is the 43-character canonical one.
	if len(s) != 43 {
		return d, fmt.Errorf("%w: digest is not canonical unpadded base64url of 32 bytes", ErrIntent)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return d, fmt.Errorf("%w: digest is not canonical unpadded base64url of 32 bytes", ErrIntent)
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != len(d) {
		return d, fmt.Errorf("%w: digest is not canonical unpadded base64url of 32 bytes", ErrIntent)
	}
	copy(d[:], raw)
	return d, nil
}

// EIP3009Nonce derives the EIP-3009 bytes32 nonce for a payment from its intent
// digest (SPEC-ARC-M3 §4.1.4):
//
//	SHA-256( "spt-txn-eip3009-nonce-v1" || 0x00 || raw_intent_digest )
//
// The preimage is always 24 + 1 + 32 = 57 bytes.
func EIP3009Nonce(d Digest) [32]byte {
	h := sha256.New()
	h.Write([]byte(EIP3009NonceTag))
	h.Write([]byte{0x00})
	h.Write(d[:])
	var n [32]byte
	copy(n[:], h.Sum(nil))
	return n
}

// Package x402v2 builds the complete x402 v2 PaymentPayload for a guarded
// EIP-3009 authorization (SPEC-ARC-M3 §4.1.5).
//
// The resource server's requirements are an input, never a template. Every
// security-relevant term is validated against the guarded authorization and the
// pinned configuration. The validated `accepted` object is then echoed exactly
// as received (insignificant whitespace removed, nothing else), because the
// reference resource server matches its core terms by exact, case-sensitive
// comparison (x402-foundation/x402 @ 7f2b2f1, go/server.go
// paymentRequirementsMatchAccepted). Nothing in `accepted` is normalized,
// re-cased or re-rendered.
//
// The payload is serialized once. The PAYMENT-SIGNATURE header value and
// payload_sha256 are both computed from those exact bytes.
//
// Provenance (owner ruling, option C): the token issuer's authorization of the
// supplied requirements does not authenticate the resource server as their
// origin. What binds the payment is the comparison against the capability and
// the pinned configuration below.
//
// Dependencies: the standard library and golang.org/x/crypto/sha3 (EIP-55).
package x402v2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/sha3"

	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// ErrRequirements is the class of every refusal.
var ErrRequirements = errors.New("x402v2: refused")

// Version is the x402 protocol version this package emits.
const Version = 2

// maxInfoLen bounds the informational resource fields.
const maxInfoLen = 256

// Config is the authenticated and pinned context the requirements are checked
// against. The asset contract, chain and EIP-712 domain come from the guarded
// authorization itself, which was bound from pinned configuration.
type Config struct {
	// Network is the capability network's CAIP-2 id, e.g. "eip155:5042002".
	Network string
	// ResourceURL is the capability's separately authenticated resource URL.
	ResourceURL string
	// MaxTimeoutCeiling bounds accepted.maxTimeoutSeconds. Must be positive.
	MaxTimeoutCeiling int
}

// Payment is the built payload.
type Payment struct {
	// JSON is the exact serialized PaymentPayload.
	JSON []byte
	// Header is the PAYMENT-SIGNATURE value: standard base64 of JSON.
	Header string
	// SHA256 is SHA-256 of JSON, before base64.
	SHA256 [32]byte
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRequirements}, a...)...)
}

// Check validates the requirements against the guarded authorization and the
// configuration without a signature. The gateway calls it before anything is
// recorded or signed; Build repeats every check.
func Check(cfg Config, b eip3009.Bound, rawAccepted, rawResource []byte) error {
	if cfg.Network == "" || cfg.ResourceURL == "" || cfg.MaxTimeoutCeiling <= 0 {
		return refuse("configuration incomplete")
	}
	auth := b.Authorization()
	if err := b.Verify(auth); err != nil {
		return err
	}
	if _, err := validateResource(cfg, rawResource); err != nil {
		return err
	}
	_, _, err := validateAccepted(cfg, auth, rawAccepted)
	return err
}

// Build validates the resource server's requirements against the guarded
// authorization and configuration, checks the signature, and emits the
// payload. sig is the 65-byte signature; recovered is the address the caller
// recovered from it over b.Digest() (see eip3009sign).
func Build(cfg Config, b eip3009.Bound, sig []byte, recovered evm.Address, rawAccepted, rawResource []byte) (Payment, error) {
	if cfg.Network == "" || cfg.ResourceURL == "" || cfg.MaxTimeoutCeiling <= 0 {
		return Payment{}, refuse("configuration incomplete")
	}
	if err := b.CheckSigned(sig, recovered); err != nil {
		return Payment{}, err
	}
	auth := b.Authorization()
	if err := b.Verify(auth); err != nil { // also refuses an unbound Bound
		return Payment{}, err
	}

	resource, err := validateResource(cfg, rawResource)
	if err != nil {
		return Payment{}, err
	}
	accepted, payTo, err := validateAccepted(cfg, auth, rawAccepted)
	if err != nil {
		return Payment{}, err
	}

	// One serialization. accepted and resource are embedded as the validated
	// input, compacted; every other byte is produced here.
	var out bytes.Buffer
	out.WriteString(`{"x402Version":2,"resource":`)
	out.Write(resource)
	out.WriteString(`,"accepted":`)
	out.Write(accepted)
	out.WriteString(`,"payload":{"signature":`)
	writeJSONString(&out, "0x"+hex.EncodeToString(sig))
	out.WriteString(`,"authorization":{"from":`)
	writeJSONString(&out, checksum(auth.From))
	out.WriteString(`,"to":`)
	// The same string the server published as payTo, already validated equal
	// to the authorization's recipient.
	writeJSONString(&out, payTo)
	out.WriteString(`,"value":`)
	writeJSONString(&out, auth.Value.String())
	out.WriteString(`,"validAfter":`)
	writeJSONString(&out, auth.ValidAfter.String())
	out.WriteString(`,"validBefore":`)
	writeJSONString(&out, auth.ValidBefore.String())
	out.WriteString(`,"nonce":`)
	writeJSONString(&out, "0x"+hex.EncodeToString(auth.Nonce[:]))
	out.WriteString(`}}}`)

	j := out.Bytes()
	if !json.Valid(j) {
		return Payment{}, refuse("internal: produced invalid JSON")
	}
	return Payment{JSON: j, Header: base64.StdEncoding.EncodeToString(j), SHA256: sha256.Sum256(j)}, nil
}

// validateResource accepts {url, description?, mimeType?} only. url must equal
// the authenticated resource URL exactly; the others are informational,
// bounded, and never used in a decision.
func validateResource(cfg Config, raw []byte) ([]byte, error) {
	members, compact, err := strictObject(raw)
	if err != nil {
		return nil, refuse("resource: %v", err)
	}
	for k := range members {
		switch k {
		case "url", "description", "mimeType":
		default:
			return nil, refuse("resource: unknown member %q", k)
		}
	}
	url, err := stringMember(members, "url", true)
	if err != nil {
		return nil, refuse("resource: %v", err)
	}
	if url != cfg.ResourceURL {
		return nil, refuse("resource.url %q is not the authenticated resource URL", url)
	}
	for _, k := range []string{"description", "mimeType"} {
		s, err := stringMember(members, k, false)
		if err != nil {
			return nil, refuse("resource: %v", err)
		}
		if len(s) > maxInfoLen {
			return nil, refuse("resource.%s is longer than %d bytes", k, maxInfoLen)
		}
	}
	return compact, nil
}

// validateAccepted checks every core term and extra member, and returns the
// compacted object and the payTo string exactly as published.
func validateAccepted(cfg Config, auth eip3009.Authorization, raw []byte) ([]byte, string, error) {
	members, compact, err := strictObject(raw)
	if err != nil {
		return nil, "", refuse("accepted: %v", err)
	}
	for k := range members {
		switch k {
		case "scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra":
		default:
			return nil, "", refuse("accepted: unknown member %q", k)
		}
	}
	str := func(k string) (string, error) { return stringMember(members, k, true) }

	scheme, err := str("scheme")
	if err != nil || scheme != "exact" {
		return nil, "", refuse("accepted.scheme must be exactly \"exact\"")
	}
	network, err := str("network")
	if err != nil || network != cfg.Network {
		return nil, "", refuse("accepted.network is not the capability network %q", cfg.Network)
	}
	if chain, ok := caip2Chain(network); !ok || chain != auth.Domain.ChainID {
		return nil, "", refuse("accepted.network does not name the authorization's chain %d", auth.Domain.ChainID)
	}
	asset, err := str("asset")
	if err != nil {
		return nil, "", refuse("accepted: %v", err)
	}
	if a, err := parseAddress(asset); err != nil || a != auth.Domain.VerifyingContract {
		return nil, "", refuse("accepted.asset is not the pinned asset contract (%v)", err)
	}
	payTo, err := str("payTo")
	if err != nil {
		return nil, "", refuse("accepted: %v", err)
	}
	if a, err := parseAddress(payTo); err != nil || a != auth.To {
		return nil, "", refuse("accepted.payTo is not the authorized recipient (%v)", err)
	}
	amount, err := str("amount")
	if err != nil {
		return nil, "", refuse("accepted: %v", err)
	}
	if !canonicalUint(amount) {
		return nil, "", refuse("accepted.amount %q is not a canonical base-10 integer", amount)
	}
	if n, _ := new(big.Int).SetString(amount, 10); n.Cmp(auth.Value) != 0 {
		return nil, "", refuse("accepted.amount is not the authorized amount")
	}
	mts, ok := members["maxTimeoutSeconds"]
	if !ok {
		return nil, "", refuse("accepted.maxTimeoutSeconds is required")
	}
	if n, err := canonicalJSONInt(mts); err != nil || n < 1 || n > int64(cfg.MaxTimeoutCeiling) {
		return nil, "", refuse("accepted.maxTimeoutSeconds must be an integer in [1, %d]", cfg.MaxTimeoutCeiling)
	}
	extraRaw, ok := members["extra"]
	if !ok {
		return nil, "", refuse("accepted.extra (EIP-712 name and version) is required")
	}
	extra, _, err := strictObject(extraRaw)
	if err != nil {
		return nil, "", refuse("accepted.extra: %v", err)
	}
	for k := range extra {
		switch k {
		case "name", "version", "assetTransferMethod":
		default:
			return nil, "", refuse("accepted.extra: unknown member %q", k)
		}
	}
	name, err := stringMember(extra, "name", true)
	if err != nil || name != auth.Domain.Name {
		return nil, "", refuse("accepted.extra.name is not the pinned EIP-712 domain name (configuration error)")
	}
	version, err := stringMember(extra, "version", true)
	if err != nil || version != auth.Domain.Version {
		return nil, "", refuse("accepted.extra.version is not the pinned EIP-712 domain version (configuration error)")
	}
	if _, present := extra["assetTransferMethod"]; present {
		m, err := stringMember(extra, "assetTransferMethod", true)
		if err != nil || m != "eip3009" {
			return nil, "", refuse("accepted.extra.assetTransferMethod must be absent or \"eip3009\"")
		}
	}
	return compact, payTo, nil
}

// strictObject parses one JSON object, refusing duplicate member names at
// every depth, invalid UTF-8 and trailing data. It returns the top-level
// members and the compacted input (insignificant whitespace removed; member
// order, string escapes and number spellings unchanged).
func strictObject(raw []byte) (map[string]json.RawMessage, []byte, error) {
	if !utf8.Valid(raw) {
		return nil, nil, errors.New("invalid UTF-8")
	}
	if err := noDuplicates(raw); err != nil {
		return nil, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, errors.New("not a JSON object")
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		members[kt.(string)] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("data after the object")
	}
	var c bytes.Buffer
	if err := json.Compact(&c, raw); err != nil {
		return nil, nil, err
	}
	return members, c.Bytes(), nil
}

// noDuplicates walks the whole value and refuses a repeated member name in any
// object.
func noDuplicates(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k := kt.(string)
				if seen[k] {
					return fmt.Errorf("duplicate member %q", k)
				}
				seen[k] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token() // closing delimiter
		return err
	}
	return walk()
}

func stringMember(m map[string]json.RawMessage, k string, required bool) (string, error) {
	v, ok := m[k]
	if !ok {
		if required {
			return "", fmt.Errorf("%s is required", k)
		}
		return "", nil
	}
	t := bytes.TrimSpace(v)
	if len(t) == 0 || t[0] != '"' {
		return "", fmt.Errorf("%s must be a JSON string", k)
	}
	var s string
	if err := json.Unmarshal(t, &s); err != nil {
		return "", fmt.Errorf("%s: %v", k, err)
	}
	return s, nil
}

// canonicalUint is a positive base-10 integer with no sign, no leading zero and
// no whitespace, at most 78 digits (uint256).
func canonicalUint(s string) bool {
	if s == "" || len(s) > 78 || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// canonicalJSONInt accepts a JSON number written as a canonical integer.
func canonicalJSONInt(raw json.RawMessage) (int64, error) {
	s := string(bytes.TrimSpace(raw))
	body := strings.TrimPrefix(s, "-")
	if body == "" || (len(body) > 1 && body[0] == '0') || s == "-0" {
		return 0, errors.New("not a canonical integer")
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return 0, errors.New("not a canonical integer")
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

// caip2Chain parses "eip155:<n>" with a canonical decimal n.
func caip2Chain(s string) (uint64, bool) {
	rest, ok := strings.CutPrefix(s, "eip155:")
	if !ok || !canonicalUint(rest) {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	return n, err == nil
}

// parseAddress accepts "0x" + 40 hex digits. All-lowercase and all-uppercase
// digits carry no checksum; mixed case must be a valid EIP-55 checksum.
func parseAddress(s string) (evm.Address, error) {
	var a evm.Address
	if len(s) != 42 || s[:2] != "0x" {
		return a, errors.New("not 0x + 40 hex digits")
	}
	body := s[2:]
	if _, err := hex.Decode(a[:], []byte(body)); err != nil {
		return evm.Address{}, errors.New("not 0x + 40 hex digits")
	}
	lower, upper := strings.ToLower(body), strings.ToUpper(body)
	if body != lower && body != upper && checksum(a) != s {
		return evm.Address{}, errors.New("mixed-case address with an invalid EIP-55 checksum")
	}
	return a, nil
}

// checksum is the EIP-55 form of a.
func checksum(a evm.Address) string {
	lower := hex.EncodeToString(a[:])
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(lower))
	sum := h.Sum(nil)
	out := []byte(lower)
	for i := range out {
		if out[i] >= 'a' && out[i] <= 'f' {
			nibble := sum[i/2]
			if i%2 == 0 {
				nibble >>= 4
			}
			if nibble&0x0f >= 8 {
				out[i] -= 'a' - 'A'
			}
		}
	}
	return "0x" + string(out)
}

func writeJSONString(b *bytes.Buffer, s string) {
	j, _ := json.Marshal(s) // only hex digits and "0x" reach here
	b.Write(j)
}

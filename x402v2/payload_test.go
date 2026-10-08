package x402v2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

var (
	now      = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	usdc     = evm.MustParseAddress("0x3600000000000000000000000000000000000000")
	payer    = evm.MustParseAddress("0x1111111111111111111111111111111111111111")
	merchant = evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d")
	cfg      = Config{Network: "eip155:5042002", ResourceURL: "https://api.example.com/invoice/42", MaxTimeoutCeiling: 300}
	sig      = func() []byte { s := make([]byte, 65); s[31], s[63], s[64] = 1, 1, 27; return s }()
)

const (
	// The server's spelling: lowercase payTo, as a server might publish it.
	goodAccepted = `{"scheme":"exact","network":"eip155:5042002","amount":"500000","asset":"0x3600000000000000000000000000000000000000","payTo":"0x79a34cc563f848f626038ff312ccebfb5374971d","maxTimeoutSeconds":60,"extra":{"name":"USDC","version":"2"}}`
	goodResource = `{"url":"https://api.example.com/invoice/42","description":"Invoice 42","mimeType":"application/json"}`
)

func bound(t *testing.T) eip3009.Bound {
	t.Helper()
	b, err := eip3009.Bind(eip3009.Binding{
		Domain: eip3009.Domain{Name: "USDC", Version: "2", ChainID: 5042002, VerifyingContract: usdc},
		From:   payer, To: merchant, Value: big.NewInt(500_000), Intent: intent.Digest{9},
		CapabilityExpiry: now.Add(time.Hour), CallExpiry: now.Add(time.Minute), MaxLifetime: 2 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func build(t *testing.T, accepted, resource string) (Payment, error) {
	t.Helper()
	return Build(cfg, bound(t), sig, payer, []byte(accepted), []byte(resource))
}

func mustBuild(t *testing.T, accepted, resource string) Payment {
	t.Helper()
	p, err := build(t, accepted, resource)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// members returns the top-level members of the payload as raw bytes.
func members(t *testing.T, j []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(j, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPayloadEchoesAcceptedExactlyAndCarriesTheAuthorization(t *testing.T) {
	p := mustBuild(t, goodAccepted, goodResource)
	m := members(t, p.JSON)
	if string(m["accepted"]) != goodAccepted {
		t.Fatalf("accepted is not the validated input byte for byte:\n got %s\nwant %s", m["accepted"], goodAccepted)
	}
	if string(m["resource"]) != goodResource || string(m["x402Version"]) != "2" {
		t.Fatalf("resource/version: %s %s", m["resource"], m["x402Version"])
	}
	var pl struct {
		Signature     string            `json:"signature"`
		Authorization map[string]string `json:"authorization"`
	}
	if err := json.Unmarshal(m["payload"], &pl); err != nil {
		t.Fatal(err)
	}
	a := bound(t).Authorization()
	n := intent.EIP3009Nonce(intent.Digest{9})
	if pl.Authorization["to"] != "0x79a34cc563f848f626038ff312ccebfb5374971d" || // the server's own spelling
		pl.Authorization["from"] != "0x1111111111111111111111111111111111111111" ||
		pl.Authorization["value"] != "500000" || pl.Authorization["validAfter"] != "0" ||
		pl.Authorization["validBefore"] != a.ValidBefore.String() ||
		pl.Authorization["nonce"] != "0x"+strings.ToLower(hexOf(n[:])) || len(pl.Signature) != 132 {
		t.Fatalf("payload %+v", pl)
	}
}

// §3.3: one serialization; the header and the hash are of the same bytes.
func TestHeaderAndHashAreOfTheExactJSONBytes(t *testing.T) {
	p := mustBuild(t, goodAccepted, goodResource)
	dec, err := base64.StdEncoding.DecodeString(p.Header)
	if err != nil || !bytes.Equal(dec, p.JSON) {
		t.Fatal("header does not decode to the payload bytes")
	}
	if p.SHA256 != sha256.Sum256(p.JSON) || p.SHA256 != sha256.Sum256(dec) {
		t.Fatal("payload_sha256 is not SHA-256 of the exact JSON bytes")
	}
	// Deterministic: the same inputs give the same bytes.
	if q := mustBuild(t, goodAccepted, goodResource); !bytes.Equal(p.JSON, q.JSON) {
		t.Fatal("not deterministic")
	}
	// Tampering with the header is visible against the recorded hash.
	t2 := []byte(p.Header)
	t2[40] ^= 1
	if d2, err := base64.StdEncoding.DecodeString(string(t2)); err == nil && sha256.Sum256(d2) == p.SHA256 {
		t.Fatal("a tampered header still matches payload_sha256")
	}
}

// Whitespace is the only thing removed; member order, escapes and number
// spellings survive.
func TestAcceptedIsCompactedNotReconstructed(t *testing.T) {
	spaced := "{ \"extra\" : {\"version\":\"2\",\"name\":\"\\u0055SDC\"},\n \"payTo\":\"0x79a34cc563f848f626038ff312ccebfb5374971d\",\"maxTimeoutSeconds\":60,\"asset\":\"0x3600000000000000000000000000000000000000\",\"amount\":\"500000\",\"network\":\"eip155:5042002\",\"scheme\":\"exact\" }"
	p := mustBuild(t, spaced, goodResource)
	var c bytes.Buffer
	_ = json.Compact(&c, []byte(spaced))
	if got := members(t, p.JSON)["accepted"]; !bytes.Equal(got, c.Bytes()) || !bytes.Contains(got, []byte(`\u0055SDC`)) {
		t.Fatalf("accepted was rewritten: %s", got)
	}
}

func TestChecksumHandling(t *testing.T) {
	// EIP-55 published examples.
	for _, s := range []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	} {
		a, err := parseAddress(s)
		if err != nil || checksum(a) != s {
			t.Fatalf("EIP-55 example %s: %v / %s", s, err, checksum(a))
		}
	}
	good := "0x79A34Cc563f848f626038Ff312CCEBfb5374971d" // valid checksum
	if checksum(merchant) != good {
		t.Fatalf("checksum(merchant) = %s", checksum(merchant))
	}
	for _, c := range []struct {
		payTo string
		ok    bool
	}{
		{good, true},
		{strings.ToLower(good), true},
		{"0x" + strings.ToUpper(good[2:]), true},
		{"0x79a34Cc563f848f626038Ff312CCEBfb5374971d", false}, // one letter's case flipped: bad checksum
		{"0X79A34Cc563f848f626038Ff312CCEBfb5374971d", false},
		{good[:41], false},
		{good + "0", false},
		{"0x79A34Cc563f848f626038Ff312CCEBfb5374971g", false},
	} {
		acc := strings.Replace(goodAccepted, "0x79a34cc563f848f626038ff312ccebfb5374971d", c.payTo, 1)
		p, err := build(t, acc, goodResource)
		if c.ok {
			if err != nil {
				t.Errorf("%s refused: %v", c.payTo, err)
				continue
			}
			// The server's spelling is echoed, never re-cased.
			if !bytes.Contains(members(t, p.JSON)["accepted"], []byte(c.payTo)) {
				t.Errorf("%s was re-cased", c.payTo)
			}
		} else if !errors.Is(err, ErrRequirements) {
			t.Errorf("%s accepted", c.payTo)
		}
	}
}

// Every refusal the owner listed, each against the otherwise good input.
func TestRefusals(t *testing.T) {
	rep := func(old, new string) string { return strings.Replace(goodAccepted, old, new, 1) }
	cases := map[string][2]string{
		// case-sensitive exact matching of terms the server compares
		"scheme cased":         {rep(`"exact"`, `"Exact"`), goodResource},
		"network cased":        {rep(`"eip155:5042002"`, `"EIP155:5042002"`), goodResource},
		"network mainnet":      {rep(`"eip155:5042002"`, `"eip155:5042"`), goodResource},
		"network leading zero": {rep(`"eip155:5042002"`, `"eip155:05042002"`), goodResource},
		"asset other contract": {rep(`0x3600000000000000000000000000000000000000`, `0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a`), goodResource},
		"payTo other":          {rep(`0x79a34cc563f848f626038ff312ccebfb5374971d`, `0x00000000000000000000000000000000000000aa`), goodResource},
		// amount canonicalization: refused, never normalized
		"amount leading zero": {rep(`"500000"`, `"0500000"`), goodResource},
		"amount plus sign":    {rep(`"500000"`, `"+500000"`), goodResource},
		"amount space":        {rep(`"500000"`, `" 500000"`), goodResource},
		"amount decimal":      {rep(`"500000"`, `"500000.0"`), goodResource},
		"amount exponent":     {rep(`"500000"`, `"5e5"`), goodResource},
		"amount hex":          {rep(`"500000"`, `"0x7a120"`), goodResource},
		"amount number":       {rep(`"500000"`, `500000`), goodResource},
		"amount differs":      {rep(`"500000"`, `"500001"`), goodResource},
		"amount zero":         {rep(`"500000"`, `"0"`), goodResource},
		// pinned domain
		"domain name":       {rep(`"name":"USDC"`, `"name":"USD Coin"`), goodResource},
		"domain name cased": {rep(`"name":"USDC"`, `"name":"usdc"`), goodResource},
		"domain version":    {rep(`"version":"2"`, `"version":"1"`), goodResource},
		"extra absent":      {rep(`,"extra":{"name":"USDC","version":"2"}`, ``), goodResource},
		"transfer method":   {rep(`"version":"2"}`, `"version":"2","assetTransferMethod":"permit2"}`), goodResource},
		"batching contract": {rep(`"version":"2"}`, `"version":"2","verifyingContract":"0x0077777d7EBA4688BDeF3E311b846F25870A19B9"}`), goodResource},
		// duplicate and unknown members, at every level
		"duplicate payTo":      {rep(`"payTo":`, `"payTo":"0x00000000000000000000000000000000000000aa","payTo":`), goodResource},
		"duplicate in extra":   {rep(`"name":"USDC"`, `"name":"USDC","name":"USDC"`), goodResource},
		"unknown member":       {rep(`"scheme"`, `"memo":"x","scheme"`), goodResource},
		"mis-cased member":     {rep(`"payTo"`, `"PayTo"`), goodResource},
		"timeout absent":       {rep(`,"maxTimeoutSeconds":60`, ``), goodResource},
		"timeout zero":         {rep(`"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":0`), goodResource},
		"timeout over ceiling": {rep(`"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":301`), goodResource},
		"timeout fraction":     {rep(`"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":60.0`), goodResource},
		"timeout string":       {rep(`"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":"60"`), goodResource},
		"trailing data":        {goodAccepted + `{}`, goodResource},
		"not an object":        {`["exact"]`, goodResource},
		// resource
		"resource url differs":    {goodAccepted, strings.Replace(goodResource, "/invoice/42", "/invoice/43", 1)},
		"resource url cased":      {goodAccepted, strings.Replace(goodResource, "https://api", "HTTPS://api", 1)},
		"resource url trailing /": {goodAccepted, strings.Replace(goodResource, "/invoice/42", "/invoice/42/", 1)},
		"resource url absent":     {goodAccepted, `{"description":"x"}`},
		"resource unknown":        {goodAccepted, strings.Replace(goodResource, `"mimeType"`, `"serviceName":"x","mimeType"`, 1)},
		"resource duplicate url":  {goodAccepted, strings.Replace(goodResource, `{"url"`, `{"url":"https://api.example.com/invoice/42","url"`, 1)},
		"description too long":    {goodAccepted, strings.Replace(goodResource, "Invoice 42", strings.Repeat("a", 257), 1)},
		"description number":      {goodAccepted, strings.Replace(goodResource, `"Invoice 42"`, `42`, 1)},
	}
	for name, c := range cases {
		if _, err := build(t, c[0], c[1]); !errors.Is(err, ErrRequirements) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	// The ceiling itself is accepted.
	if _, err := build(t, strings.Replace(goodAccepted, `"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":300`, 1), goodResource); err != nil {
		t.Errorf("maxTimeoutSeconds at the ceiling refused: %v", err)
	}
	// A description of exactly 256 bytes is informational and accepted.
	if _, err := build(t, goodAccepted, strings.Replace(goodResource, "Invoice 42", strings.Repeat("a", 256), 1)); err != nil {
		t.Errorf("256-byte description refused: %v", err)
	}
}

// The signature and the payment terms must agree before any payload exists.
func TestNoPayloadWithoutAGuardedSignature(t *testing.T) {
	b := bound(t)
	other := evm.MustParseAddress("0x00000000000000000000000000000000000000bb")
	high := append([]byte(nil), sig...)
	for i := 32; i < 64; i++ {
		high[i] = 0xff
	}
	for name, c := range map[string]struct {
		sig []byte
		who evm.Address
	}{
		"recovers to another account": {sig, other},
		"high-s":                      {high, payer},
		"short":                       {sig[:64], payer},
	} {
		if _, err := Build(cfg, b, c.sig, c.who, []byte(goodAccepted), []byte(goodResource)); err == nil {
			t.Errorf("%s: payload produced", name)
		}
	}
	if _, err := Build(cfg, eip3009.Bound{}, sig, payer, []byte(goodAccepted), []byte(goodResource)); err == nil {
		t.Error("payload produced for an unvalidated binding")
	}
	for name, c := range map[string]Config{
		"no network":      {ResourceURL: cfg.ResourceURL, MaxTimeoutCeiling: 300},
		"no resource url": {Network: cfg.Network, MaxTimeoutCeiling: 300},
		"no ceiling":      {Network: cfg.Network, ResourceURL: cfg.ResourceURL},
		"other network":   {Network: "eip155:5042", ResourceURL: cfg.ResourceURL, MaxTimeoutCeiling: 300},
	} {
		if _, err := Build(c, b, sig, payer, []byte(goodAccepted), []byte(goodResource)); err == nil {
			t.Errorf("config %s: payload produced", name)
		}
	}
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}

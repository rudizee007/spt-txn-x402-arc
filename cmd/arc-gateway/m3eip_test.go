//go:build arc

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rudizee007/spt-txn-x402-arc/correlation"
	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009/eip3009sign"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/x402v2"
)

// SPEC-ARC-M3 §4.1.5 and §6.3 through the gateway: requirements checked before
// anything is recorded or signed; the payload released only after its 0x02
// completion record is persisted; signing never retried.

const (
	resourceURL = "https://api.example.com/premium/42"
	// The server's own spelling of payTo (lowercase) and member order.
	acceptedJSON = `{"scheme":"exact","network":"eip155:5042002","amount":"500000","asset":"0x3600000000000000000000000000000000000000","payTo":"0x79a34cc563f848f626038ff312ccebfb5374971d","maxTimeoutSeconds":60,"extra":{"name":"USDC","version":"2"}}`
	resourceJSON = `{"url":"` + resourceURL + `","description":"premium report"}`
)

// eipFixture is a live-mode EIP-3009 gateway with a counting local signer.
type eipFixture struct {
	s       *server
	signs   *int
	sigs    *[][]byte // every signature the signer produced
	corr    string    // correlation file path
	diag    *bytes.Buffer
	out     *bytes.Buffer
	key     *ecdsa.PrivateKey
	auth    *fixedAuthorizer
	logPub  ed25519.PublicKey
	signErr error // returned after signing, to model an uncertain remote outcome
}

func newEIP(t *testing.T) *eipFixture {
	t.Helper()
	f := &eipFixture{signs: new(int), sigs: new([][]byte), diag: new(bytes.Buffer), out: new(bytes.Buffer), auth: allowAt0()}
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.key = k
	logKey := ed25519.NewKeyFromSeed(logSeed[:])
	f.logPub = logKey.Public().(ed25519.PublicKey)
	f.corr = filepath.Join(t.TempDir(), "correlation")
	cf, err := correlation.Open(f.corr, f.logPub)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cf.Close() })
	s := newTestServer(f.auth, nil, new(int))
	s.cap.ResourceURL = resourceURL
	s.out, s.diag = f.out, f.diag
	s.m3 = &m3{
		identity: identity, corr: cf, logKey: logKey, rail: railEIP3009,
		logHash: func(seq uint64) ([32]byte, bool) { return logEntryHex, seq == 0 },
		domain:  eip3009.Domain{Name: "USDC", Version: "2", ChainID: testCap.Net.ChainID, VerifyingContract: testCap.Net.USDC},
		maxLife: 5 * time.Minute,
		payer:   evm.Address(crypto.PubkeyToAddress(k.PublicKey)),
		x402:    x402Config(),
	}
	s.m3.signEIP = func(_ context.Context, b eip3009.Bound) ([]byte, error) {
		*f.signs++
		sig, err := eip3009sign.Sign(b, k)
		if err != nil {
			return nil, err
		}
		*f.sigs = append(*f.sigs, sig)
		return sig, f.signErr
	}
	f.s = s
	return f
}

func x402Config() x402v2.Config {
	return x402v2.Config{Network: testCap.Net.CAIP2, ResourceURL: resourceURL, MaxTimeoutCeiling: maxTimeoutCeiling}
}

func argsEIP(pid, accepted, resource string) string {
	return `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42","payment_id":"` + pid +
		`","server_identity":"` + identity + `","x402_accepted":` + accepted + `,"x402_resource":` + resource + `}`
}

// rpc sends one tools/call through server.handle, as the protocol loop does.
func (f *eipFixture) rpc(t *testing.T, args string) (text string, isErr bool) {
	t.Helper()
	f.out.Reset()
	params := json.RawMessage(`{"name":"` + f.s.toolName() + `","arguments":` + args + `}`)
	f.s.handle(context.Background(), rpcReq{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})
	var resp struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
			IsError bool                    `json:"isError"`
		} `json:"result"`
	}
	if f.out.Len() == 0 {
		return "", true
	}
	if err := json.Unmarshal(f.out.Bytes(), &resp); err != nil || len(resp.Result.Content) != 1 {
		t.Fatalf("reply %q: %v", f.out, err)
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

// chain reads the correlation file from disk, as a verifier would.
func (f *eipFixture) chain(t *testing.T) correlation.Chain {
	t.Helper()
	raw, err := os.ReadFile(f.corr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := correlation.VerifyChain(raw, f.logPub)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// noSignatureOut asserts no signature the signer produced left the process.
func (f *eipFixture) noSignatureOut(t *testing.T, name string) {
	t.Helper()
	for _, sig := range *f.sigs {
		h := hex.EncodeToString(sig)
		for where, b := range map[string][]byte{"reply": f.out.Bytes(), "diagnostics": f.diag.Bytes()} {
			if bytes.Contains(b, []byte(h)) {
				t.Fatalf("%s: a signature reached the %s", name, where)
			}
		}
	}
	for _, marker := range []string{"PAYMENT-SIGNATURE", "payload: {", "x402Version"} {
		if bytes.Contains(f.out.Bytes(), []byte(marker)) {
			t.Fatalf("%s: the reply carries %q", name, marker)
		}
	}
}

func field(t *testing.T, text, name string) string {
	t.Helper()
	i := strings.Index(text, "  "+name+": ")
	if i < 0 {
		t.Fatalf("no %s in %q", name, text)
	}
	v := text[i+len(name)+4:]
	if j := strings.IndexByte(v, '\n'); j >= 0 {
		v = v[:j]
	}
	return v
}

func TestEIP3009ReleasesThePayloadItsCompletionRecordNames(t *testing.T) {
	f := newEIP(t)
	text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON))
	if isErr || *f.signs != 1 {
		t.Fatalf("eip3009 rail: %s", text)
	}
	header := field(t, text, "PAYMENT-SIGNATURE")
	payload, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	if field(t, text, "payload") != string(payload) {
		t.Fatal("the header and the payload shown differ")
	}
	sum := sha256.Sum256(payload)
	if field(t, text, "payload_sha256") != hex.EncodeToString(sum[:]) {
		t.Fatal("payload_sha256 is not the hash of the header's bytes")
	}

	// The persisted chain: one 0x01 record and one 0x02 completion naming the
	// exact bytes released.
	c := f.chain(t)
	if len(c.Records) != 1 || len(c.Completions) != 1 || c.Entries != 2 {
		t.Fatalf("chain %+v", c)
	}
	r, cp := c.Records[0], c.Completions[0]
	if cp.RefSeq != r.Seq || cp.RefHash != r.Hash() || cp.GuardedID != r.GuardedID || cp.PaymentID != r.PaymentID || cp.PayloadSHA256 != sum {
		t.Fatalf("completion %+v does not complete %+v with the released payload", cp, r)
	}

	// The payload: the server's accepted echoed byte for byte, the bound
	// authorization, the guarded digest.
	var p struct {
		X402Version int             `json:"x402Version"`
		Accepted    json.RawMessage `json:"accepted"`
		Resource    json.RawMessage `json:"resource"`
		Payload     struct {
			Signature     string
			Authorization map[string]string
		}
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	if string(p.Accepted) != acceptedJSON || string(p.Resource) != resourceJSON || p.X402Version != 2 {
		t.Fatalf("payload %s", payload)
	}
	d, _ := intent.Compute(f.s.toolName(), []byte(argsEIP(pidA, acceptedJSON, resourceJSON)), identity)
	n := intent.EIP3009Nonce(d)
	a := p.Payload.Authorization
	if a["nonce"] != "0x"+hex.EncodeToString(n[:]) || a["to"] != "0x79a34cc563f848f626038ff312ccebfb5374971d" ||
		a["value"] != "500000" || a["from"] != crypto.PubkeyToAddress(f.key.PublicKey).Hex() {
		t.Fatalf("authorization %v", a)
	}
	if vb, _ := new(big.Int).SetString(a["validBefore"], 10); vb.Int64() > t0.Add(time.Minute).Unix() {
		t.Fatalf("validBefore %s outlives the call expiry", vb)
	}
	sig, _ := hex.DecodeString(strings.TrimPrefix(p.Payload.Signature, "0x"))
	if got, err := eip3009sign.Recover(r.GuardedID, sig); err != nil || got != f.s.m3.payer {
		t.Fatalf("the signature does not recover to the payer over the recorded guarded_id: %v", err)
	}

	// The four states, in order.
	diag := f.diag.String()
	last := -1
	for _, state := range []string{"signing attempted", "completion recorded", "release attempted", "release written"} {
		i := strings.Index(diag, state)
		if i <= last {
			t.Fatalf("%q missing or out of order in:\n%s", state, diag)
		}
		last = i
	}
	if strings.Contains(diag, hex.EncodeToString(sig)) {
		t.Fatal("the signature was written to the diagnostics")
	}
}

// The release invariant: when the completion record is written, nothing of the
// payload has left the process.
func TestEIP3009NothingLeavesBeforeTheCompletionIsPersisted(t *testing.T) {
	f := newEIP(t)
	persisted := false
	f.s.m3.complete = func(refSeq uint64, sha [32]byte) (correlation.Completion, error) {
		if f.out.Len() != 0 {
			t.Fatalf("output before the completion record: %q", f.out)
		}
		f.noSignatureOut(t, "before completion")
		c, err := f.s.m3.corr.AppendCompletion(refSeq, sha, f.s.m3.logKey)
		persisted = err == nil
		return c, err
	}
	text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON))
	if isErr || !persisted || !strings.Contains(text, "PAYMENT-SIGNATURE") {
		t.Fatalf("not released after persistence: %s", text)
	}
}

// A completion that cannot be persisted withholds the payload, and signing is
// not retried; the payment_id stays consumed.
func TestEIP3009CompletionFailureWithholdsThePayload(t *testing.T) {
	for name, fail := range map[string]func(f *eipFixture) func(uint64, [32]byte) (correlation.Completion, error){
		"write refused": func(*eipFixture) func(uint64, [32]byte) (correlation.Completion, error) {
			return func(uint64, [32]byte) (correlation.Completion, error) {
				return correlation.Completion{}, errors.New("disk full")
			}
		},
		"file closed under it": func(f *eipFixture) func(uint64, [32]byte) (correlation.Completion, error) {
			return func(ref uint64, sha [32]byte) (correlation.Completion, error) {
				f.s.m3.corr.Close()
				return f.s.m3.corr.AppendCompletion(ref, sha, f.s.m3.logKey)
			}
		},
		"duplicate completion": func(f *eipFixture) func(uint64, [32]byte) (correlation.Completion, error) {
			return func(ref uint64, sha [32]byte) (correlation.Completion, error) {
				if _, err := f.s.m3.corr.AppendCompletion(ref, [32]byte{9}, f.s.m3.logKey); err != nil {
					return correlation.Completion{}, err
				}
				return f.s.m3.corr.AppendCompletion(ref, sha, f.s.m3.logKey)
			}
		},
	} {
		f := newEIP(t)
		f.s.m3.complete = fail(f)
		text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON))
		if !isErr || *f.signs != 1 || !strings.Contains(text, "withheld") || !strings.Contains(text, "not retried") {
			t.Fatalf("%s: %s", name, text)
		}
		f.noSignatureOut(t, name)
		if strings.Contains(f.diag.String(), "release attempted") {
			t.Fatalf("%s: a release was attempted", name)
		}
		// The payment_id is consumed: the same call again signs nothing.
		if text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON)); !isErr || *f.signs != 1 {
			t.Fatalf("%s: retried: %s", name, text)
		}
	}
}

// A signer error is an uncertain outcome (a remote signer may have signed): no
// retry, no payload, payment_id consumed.
func TestEIP3009UncertainSigningOutcomeIsNotRetried(t *testing.T) {
	f := newEIP(t)
	f.signErr = errors.New("context deadline exceeded")
	text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON))
	if !isErr || *f.signs != 1 || !strings.Contains(text, "not established") || !strings.Contains(text, "not retried") {
		t.Fatalf("uncertain outcome: %s", text)
	}
	f.noSignatureOut(t, "uncertain outcome")
	c := f.chain(t)
	if len(c.Records) != 1 || len(c.Completions) != 0 {
		t.Fatalf("chain %+v", c)
	}
	f.signErr = nil
	if text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON)); !isErr || *f.signs != 1 {
		t.Fatalf("the consumed payment_id signed again: %s", text)
	}
	// A signature by another key is refused by the signer's own check and
	// handled the same way.
	g := newEIP(t)
	other := testKeyECDSA(t)
	g.s.m3.signEIP = func(_ context.Context, b eip3009.Bound) ([]byte, error) {
		*g.signs++
		sig, _ := eip3009sign.Sign(b, other)
		*g.sigs = append(*g.sigs, sig)
		return sig, eip3009sign.Check(b, sig)
	}
	if text, isErr := g.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON)); !isErr || *g.signs != 1 {
		t.Fatalf("another key's signature: %s", text)
	}
	g.noSignatureOut(t, "another key")
	// A signer that returns another key's signature without an error: Build
	// refuses it after the fact, and nothing is released.
	h := newEIP(t)
	h.s.m3.signEIP = func(_ context.Context, b eip3009.Bound) ([]byte, error) {
		*h.signs++
		sig, _ := eip3009sign.Sign(b, other)
		*h.sigs = append(*h.sigs, sig)
		return sig, nil
	}
	if text, isErr := h.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON)); !isErr || !strings.Contains(text, "withheld") {
		t.Fatalf("an unchecked foreign signature: %s", text)
	}
	h.noSignatureOut(t, "unchecked foreign signature")
	if len(h.chain(t).Completions) != 0 {
		t.Fatal("a completion was recorded for a foreign signature")
	}
}

func testKeyECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A reply that cannot be written: the payload's fate is reported as unknown.
func TestEIP3009FailedReplyWriteIsReleaseOutcomeUnknown(t *testing.T) {
	f := newEIP(t)
	f.s.out = failingWriter{}
	f.s.handle(context.Background(), rpcReq{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"authorize_payment","arguments":` + argsEIP(pidA, acceptedJSON, resourceJSON) + `}`)})
	diag := f.diag.String()
	if !strings.Contains(diag, "release attempted") || !strings.Contains(diag, "release outcome unknown") || strings.Contains(diag, "release written") {
		t.Fatalf("diagnostics:\n%s", diag)
	}
	if *f.signs != 1 || len(f.chain(t).Completions) != 1 {
		t.Fatal("expected one signature and one completion")
	}
}

// Requirements that do not match the binding or the pinned configuration are
// refused before any correlation record is written or anything is signed.
func TestEIP3009BadRequirementsRecordAndSignNothing(t *testing.T) {
	rep := func(old, new string) string { return strings.Replace(acceptedJSON, old, new, 1) }
	for name, c := range map[string]struct{ accepted, resource string }{
		"amount other":           {rep(`"500000"`, `"500001"`), resourceJSON},
		"payTo other":            {rep(`0x79a34cc563f848f626038ff312ccebfb5374971d`, `0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`), resourceJSON},
		"payTo bad checksum":     {rep(`0x79a34cc563f848f626038ff312ccebfb5374971d`, `0x79A34Cc563f848f626038Ff312CCEBfb5374971D`), resourceJSON},
		"network other":          {rep(`eip155:5042002`, `eip155:5042`), resourceJSON},
		"asset other":            {rep(`0x3600000000000000000000000000000000000000`, `0x3600000000000000000000000000000000000001`), resourceJSON},
		"scheme other":           {rep(`"exact"`, `"upto"`), resourceJSON},
		"domain version other":   {rep(`"version":"2"`, `"version":"1"`), resourceJSON},
		"timeout above ceiling":  {rep(`"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":301`), resourceJSON},
		"unknown member":         {rep(`"scheme"`, `"memo":"x","scheme"`), resourceJSON},
		"resource url other":     {acceptedJSON, `{"url":"https://api.example.com/premium/43"}`},
		"resource url re-cased":  {acceptedJSON, `{"url":"https://API.example.com/premium/42"}`},
		"resource unknown":       {acceptedJSON, `{"url":"` + resourceURL + `","x":1}`},
		"resource without url":   {acceptedJSON, `{"description":"d"}`},
		"amount as number":       {rep(`"500000"`, `500000`), resourceJSON},
		"extra name other":       {rep(`"name":"USDC"`, `"name":"USD Coin"`), resourceJSON},
		"transfer method permit": {rep(`"version":"2"}`, `"version":"2","assetTransferMethod":"permit2"}`), resourceJSON},
	} {
		f := newEIP(t)
		text, isErr := f.rpc(t, argsEIP(pidA, c.accepted, c.resource))
		if !isErr || *f.signs != 0 || f.s.m3.corr.Len() != 0 {
			t.Errorf("%s: recorded or signed: %s", name, firstLine(text))
		}
		if !strings.Contains(text, "nothing was recorded or signed") {
			t.Errorf("%s: refused for another reason: %s", name, text)
		}
	}
}

// Malformed object arguments are refused before the enforcement decision: by
// the strict parser, or by the intent canonicalizer (nested duplicates).
func TestEIP3009MalformedObjectsRefusedBeforeTheDecision(t *testing.T) {
	base := `{"to":"merchant","amount_usdc":"0.5","resource":"invoice:42","payment_id":"` + pidA + `","server_identity":"` + identity + `"`
	for name, args := range map[string]string{
		"accepted absent":            base + `,"x402_resource":` + resourceJSON + `}`,
		"resource absent":            base + `,"x402_accepted":` + acceptedJSON + `}`,
		"accepted a string":          base + `,"x402_accepted":"` + strings.ReplaceAll(acceptedJSON, `"`, `\"`) + `","x402_resource":` + resourceJSON + `}`,
		"accepted an array":          base + `,"x402_accepted":[` + acceptedJSON + `],"x402_resource":` + resourceJSON + `}`,
		"accepted twice":             base + `,"x402_accepted":` + acceptedJSON + `,"x402_accepted":` + acceptedJSON + `,"x402_resource":` + resourceJSON + `}`,
		"duplicate top-level member": base + `,"x402_accepted":` + strings.Replace(acceptedJSON, `"amount"`, `"amount":"1","amount"`, 1) + `,"x402_resource":` + resourceJSON + `}`,
		"duplicate nested member":    base + `,"x402_accepted":` + strings.Replace(acceptedJSON, `"version":"2"`, `"version":"1","version":"2"`, 1) + `,"x402_resource":` + resourceJSON + `}`,
		"fractional number":          base + `,"x402_accepted":` + strings.Replace(acceptedJSON, `"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":60.0`, 1) + `,"x402_resource":` + resourceJSON + `}`,
		"lone surrogate":             base + `,"x402_accepted":` + acceptedJSON + `,"x402_resource":{"url":"` + resourceURL + `","description":"\ud800"}}`,
		"object for a string arg":    `{"to":{"a":1},"amount_usdc":"0.5","resource":"invoice:42","payment_id":"` + pidA + `","server_identity":"` + identity + `","x402_accepted":` + acceptedJSON + `,"x402_resource":` + resourceJSON + `}`,
	} {
		f := newEIP(t)
		text, isErr := f.rpc(t, args)
		if !isErr || len(f.auth.seen) != 0 || *f.signs != 0 || f.s.m3.corr.Len() != 0 {
			t.Errorf("%s: reached the decision: %s", name, firstLine(text))
		}
	}
}

// The objects are covered by the existing intent digest: the correlation record
// carries intent.Compute over the arguments exactly as received, and any change
// to accepted changes the digest and so the EIP-3009 nonce.
func TestEIP3009IntentDigestCoversTheObjects(t *testing.T) {
	digestOf := func(accepted string) [32]byte {
		f := newEIP(t)
		args := argsEIP(pidA, accepted, resourceJSON)
		if text, isErr := f.rpc(t, args); isErr {
			t.Fatalf("refused: %s", text)
		}
		want, err := intent.Compute(f.s.toolName(), []byte(args), identity)
		if err != nil {
			t.Fatal(err)
		}
		r := f.chain(t).Records[0]
		if r.IntentDigest != [32]byte(want) {
			t.Fatal("the recorded digest is not intent.Compute over the arguments as received")
		}
		return r.IntentDigest
	}
	a := digestOf(acceptedJSON)
	b := digestOf(strings.Replace(acceptedJSON, `"maxTimeoutSeconds":60`, `"maxTimeoutSeconds":61`, 1))
	if a == b {
		t.Fatal("a change to accepted did not change the intent digest")
	}
	// Whitespace and member order are not part of the value: same digest.
	spaced := "{ \"extra\":{\"version\":\"2\",\"name\":\"USDC\"}, \"scheme\":\"exact\",\"network\":\"eip155:5042002\",\"amount\":\"500000\",\"asset\":\"0x3600000000000000000000000000000000000000\",\"payTo\":\"0x79a34cc563f848f626038ff312ccebfb5374971d\",\"maxTimeoutSeconds\":60 }"
	if digestOf(spaced) != a {
		t.Fatal("the digest depends on the encoding, not the value")
	}
}

func TestEIP3009DryRunRecordsWithoutSigningOrCompleting(t *testing.T) {
	f := newEIP(t)
	f.s.mode = modeDryRun
	f.s.m3.signEIP = nil
	text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON))
	if isErr || !strings.Contains(text, "DRY RUN") || strings.Contains(text, "PAYMENT-SIGNATURE") {
		t.Fatalf("dry run: %s", text)
	}
	if c := f.chain(t); len(c.Records) != 1 || len(c.Completions) != 0 {
		t.Fatalf("chain %+v", c)
	}
}

func TestEIP3009RailRefusesWithoutTheApprovedResourceURL(t *testing.T) {
	logKey := ed25519.NewKeyFromSeed(logSeed[:])
	f := m3Flags{identity: identity, rail: railEIP3009, maxLife: time.Minute, domainName: "USDC", domainVersion: "2"}
	_, err := f.buildM3(modeDryRun, filepath.Join(t.TempDir(), "log.json"), nil, logKey, capability{Net: evm.ArcTestnet()}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "resource_url") {
		t.Fatalf("started without resource_url: %v", err)
	}
}

func TestToolsListAdvertisesTheRequirementObjects(t *testing.T) {
	f := newEIP(t)
	b, _ := json.Marshal(f.s.toolsList())
	for _, want := range []string{`"x402_accepted":{"description"`, `"x402_resource":{"description"`, `"type":"object"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("tools/list lacks %s: %s", want, b)
		}
	}
	tr := newTestServer(&fixedAuthorizer{}, nil, new(int))
	tr.m3 = newM3(t, railTransfer)
	if b, _ := json.Marshal(tr.toolsList()); strings.Contains(string(b), "x402_accepted") {
		t.Fatal("the transfer rail advertises the x402 objects")
	}
}

func TestCapabilityResourceURL(t *testing.T) {
	good := `{"network":"testnet","recipient":"0x79A34Cc563f848f626038Ff312CCEBfb5374971d","resource":"invoice:42","max_amount_micro":1000000,"expires_at":"2026-10-01T13:00:00Z"`
	cp, err := parseCapability(strings.NewReader(good+`,"resource_url":"`+resourceURL+`"}`), t0)
	if err != nil || cp.ResourceURL != resourceURL {
		t.Fatalf("good resource_url: %+v, %v", cp, err)
	}
	if cp, err := parseCapability(strings.NewReader(good+`}`), t0); err != nil || cp.ResourceURL != "" {
		t.Fatalf("absent resource_url: %v", err)
	}
	for name, v := range map[string]string{
		"http":           `"http://api.example.com/x"`,
		"empty":          `""`,
		"scheme only":    `"https://"`,
		"space":          `"https://api.example.com/a b"`,
		"tab":            `"https://api.example.com/a\tb"`,
		"newline":        `"https://api.example.com/a\nb"`,
		"del":            `"https://api.example.com/a\u007fb"`,
		"lone surrogate": `"https://api.example.com/\ud800"`,
		"too long":       `"https://` + strings.Repeat("a", 2041) + `"`,
		"number":         `1`,
		"null":           `null`,
	} {
		if _, err := parseCapability(strings.NewReader(good+`,"resource_url":`+v+`}`), t0); !errors.Is(err, errCapability) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := parseCapability(strings.NewReader(good+`,"resource_url":"`+resourceURL+`","Resource_URL":"https://evil.example"}`), t0); !errors.Is(err, errCapability) {
		t.Error("a case-folded duplicate resource_url was accepted")
	}
	if _, err := parseCapability(strings.NewReader(good+`,"resource_url":"https://`+strings.Repeat("a", 2040)+`"}`), t0); err != nil {
		t.Errorf("2048 bytes refused: %v", err)
	}
}

// Crash boundaries, seen by a gateway that reopens the correlation file: an
// authorization signed but never completed stays consumed and uncompleted; a
// completed one cannot be completed again.
func TestEIP3009ReopenAfterEachBoundary(t *testing.T) {
	reopen := func(f *eipFixture) *correlation.File {
		t.Helper()
		f.s.m3.corr.Close()
		cf, err := correlation.Open(f.corr, f.logPub)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cf.Close() })
		return cf
	}
	pid, _ := hex.DecodeString(pidA)

	// Between signing and the completion record (the process dies; modelled
	// by a completion that is never written).
	f := newEIP(t)
	f.s.m3.complete = func(uint64, [32]byte) (correlation.Completion, error) {
		return correlation.Completion{}, errors.New("process killed")
	}
	if _, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON)); !isErr {
		t.Fatal("released without a completion")
	}
	cf := reopen(f)
	if !cf.Seen([32]byte(pid)) {
		t.Fatal("the payment_id is reusable after a restart")
	}
	if _, ok := cf.Completion(0); ok {
		t.Fatal("an uncompleted authorization reads as completed")
	}
	f.s.m3.corr, f.s.m3.complete = cf, nil
	if text, isErr := f.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON)); !isErr || *f.signs != 1 {
		t.Fatalf("signed again after a restart: %s", text)
	}

	// After the completion record (the reply may or may not have left).
	g := newEIP(t)
	if _, isErr := g.rpc(t, argsEIP(pidA, acceptedJSON, resourceJSON)); isErr {
		t.Fatal("refused")
	}
	cf = reopen(g)
	cp, ok := cf.Completion(0)
	if !ok || cp.PayloadSHA256 != g.chain(t).Completions[0].PayloadSHA256 {
		t.Fatal("the completion did not survive a restart")
	}
	if _, err := cf.AppendCompletion(0, [32]byte{1}, g.s.m3.logKey); !errors.Is(err, correlation.ErrDuplicateCompletion) {
		t.Fatalf("a second completion after reopening: %v", err)
	}
}

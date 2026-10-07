package eip3009

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

var (
	now      = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	usdc     = evm.MustParseAddress("0x3600000000000000000000000000000000000000")
	eurcTest = evm.MustParseAddress("0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a")
	payer    = evm.MustParseAddress("0x1111111111111111111111111111111111111111")
	merchant = evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d")
	attacker = evm.MustParseAddress("0x00000000000000000000000000000000000000aa")
	digestA  = intent.Digest{0x3a, 0x9f, 0x1c, 0x0e, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28}
)

func testBinding() Binding {
	return Binding{
		Domain: Domain{Name: "USDC", Version: "2", ChainID: evm.ArcTestnetChainID, VerifyingContract: usdc},
		From:   payer, To: merchant, Value: big.NewInt(500_000), Intent: digestA,
		CapabilityExpiry: now.Add(time.Hour), CallExpiry: now.Add(time.Minute), MaxLifetime: 10 * time.Minute,
	}
}

func mustBind(t *testing.T, b Binding) Bound {
	t.Helper()
	bd, err := Bind(b, now)
	if err != nil {
		t.Fatal(err)
	}
	return bd
}

// The type hashes are the values Circle's FiatToken publishes.
func TestTypeHashesAreThePublishedConstants(t *testing.T) {
	if got := hex.EncodeToString(transferTypeHash[:]); got != "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267" {
		t.Fatalf("TRANSFER_WITH_AUTHORIZATION_TYPEHASH = %s", got)
	}
	if got := hex.EncodeToString(domainTypeHash[:]); got != "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f" {
		t.Fatalf("EIP712Domain type hash = %s", got)
	}
}

// Known answers computed by go-ethereum's independent EIP-712 implementation
// (signer/core/apitypes); see TestDigestMatchesGoEthereumTypedData.
func TestDigestKnownAnswers(t *testing.T) {
	b, err := os.ReadFile("testdata/eip712-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 10 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for i, v := range vs {
		a, err := v.authorization()
		if err != nil {
			t.Fatal(err)
		}
		if got := digest(a); hex.EncodeToString(got[:]) != v.Digest {
			t.Errorf("vector %d: digest %x, want %s", i, got, v.Digest)
		}
	}
}

// vector is the checked-in form of one authorization and its digest.
type vector struct {
	Name, Version, Contract, From, To, Value, ValidAfter, ValidBefore, Nonce, Digest string
	ChainID                                                                          uint64
}

func (v vector) authorization() (Authorization, error) {
	big10 := func(s string) *big.Int { n, _ := new(big.Int).SetString(s, 10); return n }
	var a Authorization
	var err error
	a.PrimaryType = PrimaryType
	a.Domain.Name, a.Domain.Version, a.Domain.ChainID = v.Name, v.Version, v.ChainID
	if a.Domain.VerifyingContract, err = evm.ParseAddress(v.Contract); err != nil {
		return a, err
	}
	if a.From, err = evm.ParseAddress(v.From); err != nil {
		return a, err
	}
	if a.To, err = evm.ParseAddress(v.To); err != nil {
		return a, err
	}
	a.Value, a.ValidAfter, a.ValidBefore = big10(v.Value), big10(v.ValidAfter), big10(v.ValidBefore)
	n, err := hex.DecodeString(v.Nonce)
	if err != nil || len(n) != 32 {
		return a, errors.New("bad nonce")
	}
	copy(a.Nonce[:], n)
	return a, nil
}

func TestBindConstructsTheBoundAuthorization(t *testing.T) {
	bd := mustBind(t, testBinding())
	a := bd.Authorization()
	if a.From != payer || a.To != merchant || a.Value.Int64() != 500_000 || a.Domain.VerifyingContract != usdc {
		t.Fatalf("constructed %+v", a)
	}
	if a.ValidAfter.Sign() != 0 {
		t.Fatalf("validAfter %s, want 0", a.ValidAfter)
	}
	if want := now.Add(time.Minute).Unix(); a.ValidBefore.Int64() != want {
		t.Fatalf("validBefore %s, want the call expiry %d", a.ValidBefore, want)
	}
	if a.Nonce != intent.EIP3009Nonce(digestA) || a.Nonce == [32]byte(digestA) {
		t.Fatal("nonce is not the derived nonce (O-1, M8)")
	}
	if err := bd.Verify(a); err != nil {
		t.Fatalf("the constructed authorization fails its own check: %v", err)
	}
	// The returned copy cannot alter the bound one.
	a.Value.SetInt64(1)
	if bd.Authorization().Value.Int64() != 500_000 {
		t.Fatal("Authorization() leaks a mutable reference")
	}
}

// §4.1.3: validBefore is the earliest of the three limits, in whole seconds
// rounded down, and an already-closed window is refused.
func TestWindowIsTheEarliestLimit(t *testing.T) {
	cases := []struct {
		name      string
		mod       func(*Binding)
		wantUnix  int64
		wantError bool
	}{
		{"call expiry earliest", func(b *Binding) {}, now.Add(time.Minute).Unix(), false},
		{"capability expiry earliest", func(b *Binding) { b.CapabilityExpiry = now.Add(30 * time.Second) }, now.Add(30 * time.Second).Unix(), false},
		{"max lifetime earliest", func(b *Binding) { b.MaxLifetime = 20 * time.Second }, now.Add(20 * time.Second).Unix(), false},
		{"sub-second limit rounds down", func(b *Binding) { b.CallExpiry = now.Add(1500 * time.Millisecond) }, now.Add(time.Second).Unix(), false},
		{"limit inside this second", func(b *Binding) { b.CallExpiry = now.Add(500 * time.Millisecond) }, 0, true},
		{"capability already expired", func(b *Binding) { b.CapabilityExpiry = now.Add(-time.Second) }, 0, true},
		{"call already expired", func(b *Binding) { b.CallExpiry = now }, 0, true},
	}
	for _, c := range cases {
		b := testBinding()
		c.mod(&b)
		bd, err := Bind(b, now)
		if c.wantError {
			if !errors.Is(err, ErrViolation) {
				t.Errorf("%s: accepted", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := bd.Authorization().ValidBefore.Int64(); got != c.wantUnix {
			t.Errorf("%s: validBefore %d, want %d", c.name, got, c.wantUnix)
		}
	}
}

func TestBindRefusesAnIncompleteBinding(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 256)
	for name, mod := range map[string]func(*Binding){
		"no domain name":      func(b *Binding) { b.Domain.Name = "" },
		"no domain version":   func(b *Binding) { b.Domain.Version = "" },
		"zero chain":          func(b *Binding) { b.Domain.ChainID = 0 },
		"zero asset":          func(b *Binding) { b.Domain.VerifyingContract = evm.Address{} },
		"zero payer":          func(b *Binding) { b.From = evm.Address{} },
		"zero recipient":      func(b *Binding) { b.To = evm.Address{} },
		"nil amount":          func(b *Binding) { b.Value = nil },
		"zero amount":         func(b *Binding) { b.Value = big.NewInt(0) },
		"negative amount":     func(b *Binding) { b.Value = big.NewInt(-1) },
		"amount over uint256": func(b *Binding) { b.Value = huge },
		"no intent digest":    func(b *Binding) { b.Intent = intent.Digest{} },
		"zero max lifetime":   func(b *Binding) { b.MaxLifetime = 0 },
		"negative lifetime":   func(b *Binding) { b.MaxLifetime = -time.Second },
		"no capability exp.":  func(b *Binding) { b.CapabilityExpiry = time.Time{} },
		"no call expiry":      func(b *Binding) { b.CallExpiry = time.Time{} },
	} {
		b := testBinding()
		mod(&b)
		if _, err := Bind(b, now); !errors.Is(err, ErrViolation) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// §7: every bound field mutated, one at a time, is refused, and the refusal
// names the assertion that caught it.
func TestEveryMutationIsRefusedByItsAssertion(t *testing.T) {
	bd := mustBind(t, testBinding())
	raw := [32]byte(digestA)
	cases := []struct {
		name, assertion string
		mod             func(*Authorization)
	}{
		{"asset swapped to EURC", "(1)", func(a *Authorization) { a.Domain.VerifyingContract = eurcTest }},
		{"chain swapped to mainnet", "(2)", func(a *Authorization) { a.Domain.ChainID = evm.ArcMainnetChainID }},
		{"domain name", "(2)", func(a *Authorization) { a.Domain.Name = "USD Coin" }},
		{"domain version", "(2)", func(a *Authorization) { a.Domain.Version = "1" }},
		{"receiveWithAuthorization", "(3)", func(a *Authorization) { a.PrimaryType = "ReceiveWithAuthorization" }},
		{"empty primary type", "(3)", func(a *Authorization) { a.PrimaryType = "" }},
		{"from another account", "(4)", func(a *Authorization) { a.From = attacker }},
		{"from zero", "(4)", func(a *Authorization) { a.From = evm.Address{} }},
		{"to the attacker", "(5)", func(a *Authorization) { a.To = attacker }},
		{"value plus one", "(6)", func(a *Authorization) { a.Value = big.NewInt(500_001) }},
		{"value minus one", "(6)", func(a *Authorization) { a.Value = big.NewInt(499_999) }},
		{"value nil", "(6)", func(a *Authorization) { a.Value = nil }},
		{"validAfter in the future", "(7)", func(a *Authorization) { a.ValidAfter = big.NewInt(now.Unix() + 1) }},
		{"validAfter negative", "(7)", func(a *Authorization) { a.ValidAfter = big.NewInt(-1) }},
		{"validAfter nil", "(7)", func(a *Authorization) { a.ValidAfter = nil }},
		{"validBefore one second longer", "(7)", func(a *Authorization) { a.ValidBefore = new(big.Int).Add(a.ValidBefore, big.NewInt(1)) }},
		{"validBefore far future", "(7)", func(a *Authorization) { a.ValidBefore = new(big.Int).Lsh(big.NewInt(1), 255) }},
		{"validBefore nil", "(7)", func(a *Authorization) { a.ValidBefore = nil }},
		{"window closed", "(7)", func(a *Authorization) { a.ValidBefore = big.NewInt(now.Unix()) }},
		{"window empty", "(7)", func(a *Authorization) { a.ValidAfter = big.NewInt(now.Unix()); a.ValidBefore = big.NewInt(now.Unix()) }},
		{"nonce is the raw intent digest", "(8)", func(a *Authorization) { a.Nonce = raw }},
		{"nonce random", "(8)", func(a *Authorization) { a.Nonce = [32]byte{1} }},
		{"nonce zero", "(8)", func(a *Authorization) { a.Nonce = [32]byte{} }},
	}
	for _, c := range cases {
		a := bd.Authorization()
		c.mod(&a)
		err := bd.Verify(a)
		if !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), c.assertion) {
			t.Errorf("%s: got %v, want a refusal by assertion %s", c.name, err, c.assertion)
		}
	}
	// A shorter window is a narrower authorization, not a violation.
	a := bd.Authorization()
	a.ValidBefore = big.NewInt(now.Unix() + 5)
	if err := bd.Verify(a); err != nil {
		t.Errorf("a shorter window refused: %v", err)
	}
}

// An authorization bound to one asset never authorizes the other, in either
// direction (C9, M4).
func TestAssetIsolation(t *testing.T) {
	for _, pair := range [][2]evm.Address{{usdc, eurcTest}, {eurcTest, usdc}} {
		b := testBinding()
		b.Domain.VerifyingContract = pair[0]
		bd := mustBind(t, b)
		a := bd.Authorization()
		a.Domain.VerifyingContract = pair[1]
		if err := bd.Verify(a); !errors.Is(err, ErrViolation) {
			t.Errorf("bound to %s, accepted for %s", pair[0].Hex(), pair[1].Hex())
		}
		other := testBinding()
		other.Domain.VerifyingContract = pair[1]
		if mustBind(t, other).Digest() == bd.Digest() {
			t.Error("the digest does not depend on the asset")
		}
	}
}

func TestCheckSignedFormAndSigner(t *testing.T) {
	bd := mustBind(t, testBinding())
	good := make([]byte, 65)
	good[31], good[63], good[64] = 1, 1, 27
	if err := bd.CheckSigned(good, payer); err != nil {
		t.Fatalf("well-formed signature by the payer refused: %v", err)
	}
	set := func(f func([]byte)) []byte { s := append([]byte(nil), good...); f(s); return s }
	n := secpN.Bytes()
	high := new(big.Int).Add(secpHalfN, big.NewInt(1)).Bytes()
	for name, c := range map[string]struct {
		sig []byte
		who evm.Address
	}{
		"recovers to another account": {good, attacker},
		"recovers to zero":            {good, evm.Address{}},
		"64 bytes":                    {good[:64], payer},
		"66 bytes":                    {append(append([]byte(nil), good...), 0), payer},
		"r zero":                      {set(func(s []byte) { s[31] = 0 }), payer},
		"s zero":                      {set(func(s []byte) { s[63] = 0 }), payer},
		"s equal to n":                {set(func(s []byte) { copy(s[32:64], n) }), payer},
		"high s":                      {set(func(s []byte) { copy(s[64-len(high):64], high) }), payer},
		"v 29":                        {set(func(s []byte) { s[64] = 29 }), payer},
		"v 2":                         {set(func(s []byte) { s[64] = 2 }), payer},
	} {
		if err := bd.CheckSigned(c.sig, c.who); !errors.Is(err, ErrViolation) {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (Bound{}).CheckSigned(good, payer); !errors.Is(err, ErrNotBound) {
		t.Error("an unvalidated Bound checked a signature")
	}
	if err := (Bound{}).Verify(bd.Authorization()); !errors.Is(err, ErrNotBound) {
		t.Error("an unvalidated Bound verified an authorization")
	}
}

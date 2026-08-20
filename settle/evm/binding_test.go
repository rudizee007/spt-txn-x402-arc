package evm

import (
	"errors"
	"strings"
	"testing"

	"github.com/rudizee007/spt-txn-pep/gate"
)

// The transport form must be exactly what the gate's canonicalizer will decode:
// base58 of 32 bytes, whose leading 12 zero bytes appear as leading '1's.
func TestAccountIDBase58_IsWhatTheGateDecodes(t *testing.T) {
	a := MustParseAddress("0x3600000000000000000000000000000000000000")
	s := AccountIDBase58(a)

	if got := strings.Count(s[:padLen], "1"); got != padLen {
		t.Fatalf("transport %q does not begin with %d '1's (leading zero bytes)", s, padLen)
	}
	// The PEP encoder is the only base58 implementation in play; assert the
	// string is exactly what it produces for the widened identifier.
	id := a.AccountID32()
	if want := gate.EncodeBase58(id[:]); s != want {
		t.Fatalf("AccountIDBase58 = %q, gate.EncodeBase58 = %q", s, want)
	}
}

func TestAccountIDBase58_DistinctAddressesDistinctTransport(t *testing.T) {
	seen := map[string]string{}
	for _, h := range []string{
		"0x0000000000000000000000000000000000000000",
		"0x0000000000000000000000000000000000000001",
		"0x3600000000000000000000000000000000000000",
		"0x2222222222222222222222222222222222222222",
		"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		"0xffffffffffffffffffffffffffffffffffffffff",
	} {
		a := MustParseAddress(h)
		s := AccountIDBase58(a)
		if prev, ok := seen[s]; ok {
			t.Fatalf("transport collision: %s and %s both encode to %q", prev, h, s)
		}
		seen[s] = h
	}
}

func TestAssertTransportMatches(t *testing.T) {
	a := MustParseAddress("0x2222222222222222222222222222222222222222")
	b := MustParseAddress("0x2222222222222222222222222222222222222223")

	if err := AssertTransportMatches(a, AccountIDBase58(a)); err != nil {
		t.Fatalf("matching transport rejected: %v", err)
	}
	for _, bad := range []string{
		AccountIDBase58(b),
		"",
		AccountIDBase58(a) + "1",
		AccountIDBase58(a)[:len(AccountIDBase58(a))-1],
		strings.ToUpper(AccountIDBase58(a)),
	} {
		if err := AssertTransportMatches(a, bad); !errors.Is(err, ErrTransportMismatch) {
			t.Fatalf("transport %q: got %v, want ErrTransportMismatch", bad, err)
		}
	}
}

// The Arc profile constants are load-bearing; pin them so a careless edit is a
// failing test rather than a payment on the wrong chain.
func TestArcProfileConstants(t *testing.T) {
	if ArcTestnetChainID != 5042002 {
		t.Fatalf("ArcTestnetChainID = %d", ArcTestnetChainID)
	}
	if ArcTestnetCAIP2 != "eip155:5042002" {
		t.Fatalf("ArcTestnetCAIP2 = %q", ArcTestnetCAIP2)
	}
	if got := USDCArcTestnet.Hex(); got != "0x3600000000000000000000000000000000000000" {
		t.Fatalf("USDCArcTestnet = %s", got)
	}
	if USDCDecimals != 6 {
		t.Fatalf("USDCDecimals = %d (the ERC-20 view; the native view's 18 is never used here)", USDCDecimals)
	}
	// The chain id is a uint64, not a *big.Int. That is the point: a pointer
	// on both sides of assertion 3 can be the SAME pointer, which turns the
	// comparison into a tautology a builder would write by accident
	// ("build the transaction for the bound chain" → tx.ChainID = b.ChainID).
	// A value type cannot alias.
	var _ uint64 = ArcTestnetChainID
}

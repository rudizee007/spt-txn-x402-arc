package evm

import (
	"errors"
	"math/big"
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

// The native/ERC-20 relation is truncation, not equality. Gas is metered at
// 18-decimal granularity, so an account that has paid gas holds a native
// balance that is not a whole number of micro-USDC — and demanding exact
// equality passes on a freshly funded wallet, then fails on its second
// transaction. That is a fail-closed bug, and it is what this test exists to
// stop coming back.
func TestAssertNativeViewConsistent(t *testing.T) {
	scale := NativeScale()
	erc20 := big.NewInt(19_898_447) // 19.898447 USDC
	exact := new(big.Int).Mul(erc20, scale)

	cases := []struct {
		name     string
		native   *big.Int
		wantDust int64
		wantErr  bool
	}{
		{"freshly funded, no gas paid yet", new(big.Int).Set(exact), 0, false},
		{"after gas: the real observed residue", new(big.Int).Add(exact, big.NewInt(50_000_000_000)), 50_000_000_000, false},
		{"one native unit of dust", new(big.Int).Add(exact, big.NewInt(1)), 1, false},
		{"dust one below the scale", new(big.Int).Add(exact, new(big.Int).Sub(scale, big.NewInt(1))), 999_999_999_999, false},
		{"dust equal to the scale means erc20 truncated wrong", new(big.Int).Add(exact, scale), 0, true},
		{"native below the erc20 view", new(big.Int).Sub(exact, big.NewInt(1)), 0, true},
		{"native is zero while erc20 is not", big.NewInt(0), 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dust, err := AssertNativeViewConsistent(c.native, erc20)
			if c.wantErr {
				if !errors.Is(err, ErrNativeViewInconsistent) {
					t.Fatalf("got %v, want ErrNativeViewInconsistent", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if dust.Int64() != c.wantDust {
				t.Fatalf("dust = %s, want %d", dust, c.wantDust)
			}
		})
	}

	// Both zero is a consistent, if uninteresting, pair.
	if _, err := AssertNativeViewConsistent(big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("zero/zero: got %v, want nil", err)
	}
	for _, bad := range [][2]*big.Int{{nil, erc20}, {exact, nil}, {big.NewInt(-1), erc20}, {exact, big.NewInt(-1)}} {
		if _, err := AssertNativeViewConsistent(bad[0], bad[1]); !errors.Is(err, ErrNativeViewInconsistent) {
			t.Fatalf("native=%v erc20=%v: got %v, want ErrNativeViewInconsistent", bad[0], bad[1], err)
		}
	}

	// NativeScale must hand back a fresh value each call.
	a, b := NativeScale(), NativeScale()
	if a == b {
		t.Fatal("NativeScale returned a shared pointer")
	}
	a.SetInt64(1)
	if b.Cmp(new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil)) != 0 {
		t.Fatal("mutating one result changed another")
	}
}

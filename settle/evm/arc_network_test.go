package evm

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
)

// The mainnet constants are as load-bearing as the testnet ones; pin them.
func TestArcMainnetProfileConstants(t *testing.T) {
	if ArcMainnetChainID != 5042 {
		t.Fatalf("ArcMainnetChainID = %d", ArcMainnetChainID)
	}
	if ArcMainnetCAIP2 != "eip155:5042" {
		t.Fatalf("ArcMainnetCAIP2 = %q", ArcMainnetCAIP2)
	}
	if got := USDCArcMainnet.Hex(); got != "0x3600000000000000000000000000000000000000" {
		t.Fatalf("USDCArcMainnet = %s", got)
	}
	if ArcMainnetNetworkTag != 4 {
		t.Fatalf("ArcMainnetNetworkTag = %d", ArcMainnetNetworkTag)
	}
}

func TestArcNetworkByName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain uint64
		caip2 string
		tag   byte
	}{
		{"testnet", ArcTestnetChainID, ArcTestnetCAIP2, ArcTestnetNetworkTag},
		{"mainnet", ArcMainnetChainID, ArcMainnetCAIP2, ArcMainnetNetworkTag},
	} {
		n, err := ArcNetworkByName(tc.name)
		if err != nil {
			t.Fatalf("ArcNetworkByName(%q) = %v", tc.name, err)
		}
		if n.Name != tc.name || n.ChainID != tc.chain || n.CAIP2 != tc.caip2 || n.NetworkTag != tc.tag {
			t.Fatalf("ArcNetworkByName(%q) = %+v", tc.name, n)
		}
		// Two fields that must agree are checked, not trusted.
		if want := fmt.Sprintf("eip155:%d", n.ChainID); n.CAIP2 != want {
			t.Fatalf("%s: CAIP2 %q does not name chain %d", tc.name, n.CAIP2, n.ChainID)
		}
	}
	for _, bad := range []string{"", "Mainnet", "MAINNET", "main", " mainnet", "mainnet ", "Testnet", "devnet", "5042", "eip155:5042"} {
		if _, err := ArcNetworkByName(bad); !errors.Is(err, ErrUnknownNetwork) {
			t.Fatalf("ArcNetworkByName(%q) = %v, want ErrUnknownNetwork", bad, err)
		}
	}
	if ArcTestnet().ChainID == ArcMainnet().ChainID || ArcTestnet().NetworkTag == ArcMainnet().NetworkTag {
		t.Fatal("the two profiles must differ in chain id and in tag")
	}
}

// USDC has the same address on both networks, so the chain id is the only
// thing separating them. A binding for one network must refuse a transaction
// built for the other, in both directions.
func TestVerify_RefusesTheOtherArcNetwork(t *testing.T) {
	for _, pair := range [][2]ArcNetwork{{ArcMainnet(), ArcTestnet()}, {ArcTestnet(), ArcMainnet()}} {
		bound, built := pair[0], pair[1]
		b, err := NewBoundPayment(Binding{
			ChainID:    bound.ChainID,
			Asset:      bound.USDC.AccountID32(),
			PayTo:      boundPayTo.AccountID32(),
			Payer:      boundPayer.AccountID32(),
			Amount:     big.NewInt(boundMicroUSDC),
			Nonce:      boundNonce,
			MaxGasCost: new(big.Int).Set(testMaxGasCost),
		})
		if err != nil {
			t.Fatalf("NewBoundPayment: %v", err)
		}
		tx, _ := validPair(t)
		tx.ChainID = built.ChainID
		if _, err := Verify(tx, b); !errors.Is(err, ErrChainIDMismatch) {
			t.Fatalf("bound to %s, built for %s: Verify = %v, want ErrChainIDMismatch", bound.Name, built.Name, err)
		}
		tx.ChainID = bound.ChainID
		if _, err := Verify(tx, b); err != nil {
			t.Fatalf("bound to and built for %s: Verify = %v, want nil", bound.Name, err)
		}
	}
}

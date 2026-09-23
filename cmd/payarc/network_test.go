//go:build arc

package main

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

var (
	testMerchant = common.HexToAddress("0x2222222222222222222222222222222222222222")
	testPayer    = common.HexToAddress("0x3333333333333333333333333333333333333333")
)

func profiles() []evm.ArcNetwork { return []evm.ArcNetwork{evm.ArcTestnet(), evm.ArcMainnet()} }

func other(net evm.ArcNetwork) evm.ArcNetwork {
	if net.Name == "mainnet" {
		return evm.ArcTestnet()
	}
	return evm.ArcMainnet()
}

// The binding, the signer, the plan and the endpoint check must all name the
// selected network. If any one of them drifts back to a fixed constant, a
// settlement is signed for one network while the operator named the other.
func TestNetworkWiring_EveryChainIDIsTheSelectedOne(t *testing.T) {
	for _, net := range profiles() {
		amount := big.NewInt(10_000)
		bound, err := newBinding(net, testMerchant, testPayer, amount, 7, big.NewInt(1_000_000))
		if err != nil {
			t.Fatalf("%s: newBinding: %v", net.Name, err)
		}
		if bound.ChainID() != net.ChainID {
			t.Fatalf("%s: binding chain id %d, want %d", net.Name, bound.ChainID(), net.ChainID)
		}
		if sc := newSigner(net).ChainID(); !sc.IsUint64() || sc.Uint64() != net.ChainID {
			t.Fatalf("%s: signer chain id %v, want %d", net.Name, sc, net.ChainID)
		}
		p := newPlan(net, testMerchant, testPayer, amount, 7, big.NewInt(2), big.NewInt(1))
		if c := p.chain(); !c.IsUint64() || c.Uint64() != net.ChainID {
			t.Fatalf("%s: plan chain id %v, want %d", net.Name, c, net.ChainID)
		}
		if p.asset != common.Address(net.USDC) {
			t.Fatalf("%s: plan asset %s, want %s", net.Name, p.asset, net.USDC.Hex())
		}
		if err := checkEndpointChain(net, new(big.Int).SetUint64(net.ChainID)); err != nil {
			t.Fatalf("%s: own endpoint refused: %v", net.Name, err)
		}
		if err := checkEndpointChain(net, new(big.Int).SetUint64(other(net).ChainID)); !errors.Is(err, errWrongNetwork) {
			t.Fatalf("%s: endpoint of %s = %v, want errWrongNetwork", net.Name, other(net).Name, err)
		}
		if err := checkEndpointChain(net, nil); !errors.Is(err, errWrongNetwork) {
			t.Fatalf("%s: nil chain id = %v, want errWrongNetwork", net.Name, err)
		}
		if err := checkEndpointChain(net, new(big.Int).Lsh(big.NewInt(1), 70)); !errors.Is(err, errWrongNetwork) {
			t.Fatalf("%s: oversized chain id = %v, want errWrongNetwork", net.Name, err)
		}
	}
}

// The plan, the binding and the signer are built together and must pass the
// guard as a set: a transaction built for the selected network verifies, and
// the same transaction under the other network's binding does not.
func TestNetworkWiring_PlanVerifiesOnlyUnderItsOwnBinding(t *testing.T) {
	for _, net := range profiles() {
		amount := big.NewInt(10_000)
		p := newPlan(net, testMerchant, testPayer, amount, 7, big.NewInt(2), big.NewInt(1))
		p.gasLimit = 60_000
		maxGasCost := new(big.Int).Mul(big.NewInt(60_000), big.NewInt(2))
		view := mustView(p, testPayer)

		own, err := newBinding(net, testMerchant, testPayer, amount, 7, maxGasCost)
		if err != nil {
			t.Fatalf("%s: newBinding: %v", net.Name, err)
		}
		if _, err := evm.Verify(view, own); err != nil {
			t.Fatalf("%s: plan under its own binding: %v", net.Name, err)
		}
		foreign, err := newBinding(other(net), testMerchant, testPayer, amount, 7, maxGasCost)
		if err != nil {
			t.Fatalf("%s: newBinding(other): %v", net.Name, err)
		}
		if _, err := evm.Verify(view, foreign); !errors.Is(err, evm.ErrChainIDMismatch) {
			t.Fatalf("%s: plan under the %s binding = %v, want ErrChainIDMismatch", net.Name, other(net).Name, err)
		}
	}
}

func TestCheckMainnetFlags(t *testing.T) {
	const def = "/home/u/.config/spt-txn/arc.key"
	main, test := evm.ArcMainnet(), evm.ArcTestnet()
	cases := []struct {
		name    string
		net     evm.ArcNetwork
		set     map[string]bool
		key     string
		wantErr bool
	}{
		{"testnet takes defaults", test, map[string]bool{}, def, false},
		{"mainnet, nothing named", main, map[string]bool{}, def, true},
		{"mainnet, amount but no key", main, map[string]bool{"amount": true}, def, true},
		{"mainnet, amount, non-default key path not named", main, map[string]bool{"amount": true}, "/k/mainnet.key", true},
		{"mainnet, key but no amount", main, map[string]bool{"key": true}, "/k/mainnet.key", true},
		{"mainnet, default key named explicitly", main, map[string]bool{"key": true, "amount": true}, def, true},
		{"mainnet, own key and amount", main, map[string]bool{"key": true, "amount": true}, "/k/mainnet.key", false},
	}
	for _, c := range cases {
		err := checkMainnetFlags(c.net, c.set, c.key, def)
		if c.wantErr && !errors.Is(err, errMainnetNeedsExplicit) {
			t.Fatalf("%s: got %v, want errMainnetNeedsExplicit", c.name, err)
		}
		if !c.wantErr && err != nil {
			t.Fatalf("%s: got %v, want nil", c.name, err)
		}
	}
}

// The offline selftest must pass on both profiles, not only the default.
func TestSelfTest_BothNetworks(t *testing.T) {
	for _, net := range profiles() {
		if rc := runSelfTest(net); rc != 0 {
			t.Fatalf("selftest on %s returned %d", net.Name, rc)
		}
	}
}

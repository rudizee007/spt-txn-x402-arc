//go:build arc

package arcpay

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
		bound, err := NewBinding(net, testMerchant, testPayer, amount, 7, big.NewInt(1_000_000))
		if err != nil {
			t.Fatalf("%s: newBinding: %v", net.Name, err)
		}
		if bound.ChainID() != net.ChainID {
			t.Fatalf("%s: binding chain id %d, want %d", net.Name, bound.ChainID(), net.ChainID)
		}
		if sc := NewSigner(net).ChainID(); !sc.IsUint64() || sc.Uint64() != net.ChainID {
			t.Fatalf("%s: signer chain id %v, want %d", net.Name, sc, net.ChainID)
		}
		p := NewPlan(net, testMerchant, testPayer, amount, 7, big.NewInt(2), big.NewInt(1))
		if c := p.chain(); !c.IsUint64() || c.Uint64() != net.ChainID {
			t.Fatalf("%s: plan chain id %v, want %d", net.Name, c, net.ChainID)
		}
		if p.Asset != common.Address(net.USDC) {
			t.Fatalf("%s: plan asset %s, want %s", net.Name, p.Asset, net.USDC.Hex())
		}
		if err := CheckEndpointChain(net, new(big.Int).SetUint64(net.ChainID)); err != nil {
			t.Fatalf("%s: own endpoint refused: %v", net.Name, err)
		}
		if err := CheckEndpointChain(net, new(big.Int).SetUint64(other(net).ChainID)); !errors.Is(err, ErrWrongNetwork) {
			t.Fatalf("%s: endpoint of %s = %v, want ErrWrongNetwork", net.Name, other(net).Name, err)
		}
		if err := CheckEndpointChain(net, nil); !errors.Is(err, ErrWrongNetwork) {
			t.Fatalf("%s: nil chain id = %v, want ErrWrongNetwork", net.Name, err)
		}
		if err := CheckEndpointChain(net, new(big.Int).Lsh(big.NewInt(1), 70)); !errors.Is(err, ErrWrongNetwork) {
			t.Fatalf("%s: oversized chain id = %v, want ErrWrongNetwork", net.Name, err)
		}
	}
}

// The plan, the binding and the signer are built together and must pass the
// guard as a set: a transaction built for the selected network verifies, and
// the same transaction under the other network's binding does not.
func TestNetworkWiring_PlanVerifiesOnlyUnderItsOwnBinding(t *testing.T) {
	for _, net := range profiles() {
		amount := big.NewInt(10_000)
		p := NewPlan(net, testMerchant, testPayer, amount, 7, big.NewInt(2), big.NewInt(1))
		p.GasLimit = 60_000
		maxGasCost := new(big.Int).Mul(big.NewInt(60_000), big.NewInt(2))
		tx, err := p.Build()
		if err != nil {
			t.Fatalf("%s: build: %v", net.Name, err)
		}
		view, err := ViewOf(tx, evm.Address(testPayer))
		if err != nil {
			t.Fatalf("%s: view: %v", net.Name, err)
		}

		own, err := NewBinding(net, testMerchant, testPayer, amount, 7, maxGasCost)
		if err != nil {
			t.Fatalf("%s: newBinding: %v", net.Name, err)
		}
		if _, err := evm.Verify(view, own); err != nil {
			t.Fatalf("%s: plan under its own binding: %v", net.Name, err)
		}
		foreign, err := NewBinding(other(net), testMerchant, testPayer, amount, 7, maxGasCost)
		if err != nil {
			t.Fatalf("%s: NewBinding(other): %v", net.Name, err)
		}
		if _, err := evm.Verify(view, foreign); !errors.Is(err, evm.ErrChainIDMismatch) {
			t.Fatalf("%s: plan under the %s binding = %v, want ErrChainIDMismatch", net.Name, other(net).Name, err)
		}
	}
}

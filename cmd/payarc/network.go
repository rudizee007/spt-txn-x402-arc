//go:build arc

package main

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// Everything the -network flag decides is built here, from the one selected
// profile, so network_test.go can check that the binding, the signer, the plan
// and the endpoint check all name the same chain. The testnet and mainnet USDC
// addresses are identical, so the chain id is the only thing keeping a
// settlement on the network the operator named (SPEC-X402-ARC §A.1).

// newBinding binds the payment to the selected network's chain id and USDC.
func newBinding(net evm.ArcNetwork, merchant, payer common.Address, amount *big.Int, nonce uint64, maxGasCost *big.Int) (evm.BoundPayment, error) {
	return evm.NewBoundPayment(evm.Binding{
		ChainID:    net.ChainID,
		Asset:      net.USDC.AccountID32(),
		PayTo:      evm.Address(merchant).AccountID32(),
		Payer:      evm.Address(payer).AccountID32(),
		Amount:     new(big.Int).Set(amount),
		Nonce:      nonce,
		MaxGasCost: maxGasCost,
	})
}

// newSigner returns a signer whose chain id — the one hashed into the EIP-155
// signing preimage — is the selected network's.
func newSigner(net evm.ArcNetwork) types.Signer {
	return types.LatestSignerForChainID(new(big.Int).SetUint64(net.ChainID))
}

// newPlan returns the untampered transaction plan for the selected network.
func newPlan(net evm.ArcNetwork, merchant, payer common.Address, amount *big.Int, nonce uint64, feeCap, tip *big.Int) plan {
	return plan{
		asset: common.Address(net.USDC), merchant: merchant, payer: payer,
		amount: new(big.Int).Set(amount), nonce: nonce,
		feeCap: feeCap, tip: tip, chainBase: net.ChainID,
	}
}

// errWrongNetwork reports an endpoint serving a chain other than the selected one.
var errWrongNetwork = errors.New("endpoint is on a different network")

// checkEndpointChain refuses an endpoint whose eth_chainId is not the selected
// network's. The chain id is configuration; a disagreeing endpoint is refused,
// never adopted (§A.5.12).
func checkEndpointChain(net evm.ArcNetwork, reported *big.Int) error {
	if reported == nil || !reported.IsUint64() || reported.Uint64() != net.ChainID {
		return fmt.Errorf("%w: it reports chain id %v, -network %s is bound to %d — refusing to settle",
			errWrongNetwork, reported, net.Name, net.ChainID)
	}
	return nil
}

// errMainnetNeedsExplicit reports a mainnet run that relies on a default meant
// for testnet.
var errMainnetNeedsExplicit = errors.New("mainnet moves real USDC and takes no defaults")

// checkMainnetFlags refuses a mainnet run that did not name its key file and
// its amount. The default key path is where the testnet runbook puts the faucet
// key; on mainnet that path is refused even when passed explicitly, so a demo
// key cannot spend real funds by adding one flag.
func checkMainnetFlags(net evm.ArcNetwork, set map[string]bool, keyPath, defaultKey string) error {
	if net.Name != "mainnet" {
		return nil
	}
	if !set["key"] {
		return fmt.Errorf("%w: pass -key with a key file used only for mainnet", errMainnetNeedsExplicit)
	}
	if defaultKey != "" && keyPath == defaultKey {
		return fmt.Errorf("%w: -key %s is the testnet default path; use a separate mainnet key file", errMainnetNeedsExplicit, keyPath)
	}
	if !set["amount"] {
		return fmt.Errorf("%w: pass -amount explicitly", errMainnetNeedsExplicit)
	}
	return nil
}

// rpcHint names the documented endpoint for the selected network.
func rpcHint(net evm.ArcNetwork) string {
	if net.Name == "mainnet" {
		return "Arc's docs publish https://rpc.mainnet.arc.io for mainnet"
	}
	return "Arc's docs publish https://rpc.testnet.arc.io for testnet (Circle's use-arc skill has published rpc.testnet.arc.network; confirm the live one)"
}

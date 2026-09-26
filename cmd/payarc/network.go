//go:build arc

package main

import (
	"errors"
	"fmt"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// The network wiring itself (binding, signer, plan, endpoint check) lives in
// settle/evm/arcpay so cmd/payarc and cmd/arc-gateway share it. What stays here
// is operator-facing: which flags a mainnet run must name.

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

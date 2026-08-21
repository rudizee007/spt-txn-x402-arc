package evm

import (
	"errors"
	"fmt"
	"math/big"
)

// Arc testnet network profile (docs/SPEC-X402-ARC.md §A.1).
//
// Everything here is public Arc documentation. None of it is a secret and none
// of it may be overridden by an RPC response: the chain id in particular is
// configuration the operator asserts, never a value adopted from eth_chainId
// (§A.5.8).
const (
	// ArcTestnetChainID is the EIP-155 chain id of Arc testnet.
	ArcTestnetChainID uint64 = 5042002

	// ArcTestnetCAIP2 is the CAIP-2 network identifier used as the gate's
	// allowlist key.
	ArcTestnetCAIP2 = "eip155:5042002"

	// ArcTestnetExplorerTxPrefix renders a settled transaction for a human.
	ArcTestnetExplorerTxPrefix = "https://testnet.arcscan.app/tx/"

	// USDCFaucet issues Arc testnet USDC.
	USDCFaucet = "https://faucet.circle.com"

	// USDCDecimals is the decimal precision of USDC's ERC-20 view — the view
	// every bound amount in this profile is expressed in.
	//
	// USDC on Arc is ALSO the native gas asset, where the same funds are
	// counted with 18 decimals. The two views are one pool of money, and this
	// package never converts between them (§A.5.7).
	USDCDecimals uint8 = 6

	// ArcTestnetNetworkTag is this deployment's u8 allowlist tag for
	// ArcTestnetCAIP2. Tags are deployment configuration and are permanent once
	// assigned, because they are hashed into every binding (SPEC-X402 §4).
	// 1 and 2 are already spent on solana:devnet in this tree.
	ArcTestnetNetworkTag byte = 3
)

// USDCArcTestnet is the USDC ERC-20 interface on Arc testnet.
var USDCArcTestnet = MustParseAddress("0x3600000000000000000000000000000000000000")

// NativeScale is the ratio between USDC's native view (18 decimals) and its
// ERC-20 view (6 decimals) on Arc: 10^12 native units per micro-USDC. Returned
// fresh each call so no caller can mutate a shared value.
func NativeScale() *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil) }

// ErrNativeViewInconsistent reports that the two views of USDC do not look like
// one pool of funds related by 10^12 — which would mean the fee ceiling is
// denominated in something other than what this profile assumes.
var ErrNativeViewInconsistent = errors.New("settle/evm: native and ERC-20 balances are not one pool related by 10^12")

// AssertNativeViewConsistent checks §A.1's headline assumption against real
// chain state: the native balance and the ERC-20 balance of the same account
// are two views of ONE pool of funds, related by NativeScale.
//
// The relation is TRUNCATION, not exact equality. Gas is metered at native
// (18-decimal) granularity, so after any transaction the native balance is not
// a whole number of micro-USDC, and balanceOf reports the floor. The invariant
// is therefore
//
//	erc20 == native / 10^12    equivalently    0 <= native - erc20*10^12 < 10^12
//
// Demanding exact equality holds only for an account that has never paid gas —
// it passes on a freshly funded wallet and then fails on the second
// transaction, which is a fail-closed bug, not a safety property.
//
// The remaining dust is returned rather than discarded so a caller can display
// it instead of asserting it.
func AssertNativeViewConsistent(native, erc20 *big.Int) (*big.Int, error) {
	if native == nil || erc20 == nil {
		return nil, fmt.Errorf("%w: a balance is missing", ErrNativeViewInconsistent)
	}
	if native.Sign() < 0 || erc20.Sign() < 0 {
		return nil, fmt.Errorf("%w: a balance is negative", ErrNativeViewInconsistent)
	}
	scale := NativeScale()
	dust := new(big.Int).Sub(native, new(big.Int).Mul(erc20, scale))
	if dust.Sign() < 0 || dust.Cmp(scale) >= 0 {
		return nil, fmt.Errorf("%w: native %s, erc20 %s, residue %s is outside [0, 10^12)",
			ErrNativeViewInconsistent, native, erc20, dust)
	}
	return dust, nil
}

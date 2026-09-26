//go:build arc

package arcpay

import (
	"context"
	"fmt"
	"math/big"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// AssertSelector is the differential check on the one hardcoded constant.
// settle/evm hardcodes the ERC-20 transfer selector because it computes no
// Keccak; this package links an audited Keccak, so it re-derives the selector
// and refuses to run on disagreement (§A.3).
func AssertSelector() error {
	want := crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
	got := evm.TransferSelector()
	if string(want) != string(got[:]) {
		return fmt.Errorf("selector differential FAILED: keccak256(\"transfer(address,uint256)\")[:4] = %x, settle/evm has %x", want, got)
	}
	return nil
}

// AssertNativeRatio checks the 18-vs-6 decimal assumption against the chain
// instead of trusting it. On Arc the native balance and the ERC-20 balance are
// two views of THE SAME funds. If that relation does not hold, the fee ceiling
// is denominated in something other than what we think and §A.4 assertion 7
// would be off by twelve orders of magnitude while still printing PASS.
//
// The relation is truncation, not equality: gas is metered at native
// granularity, so any account that has paid gas holds a native balance that is
// not a whole number of micro-USDC. The arithmetic lives in settle/evm, where
// it is unit-tested; this function only fetches. It returns the residue.
func AssertNativeRatio(ctx context.Context, c *ethclient.Client, payer common.Address, erc20 *big.Int) (*big.Int, error) {
	native, err := c.BalanceAt(ctx, payer, nil)
	if err != nil {
		return nil, fmt.Errorf("native balance: %w", err)
	}
	dust, err := evm.AssertNativeViewConsistent(native, erc20)
	if err != nil {
		return nil, fmt.Errorf("%w.\n"+
			"  This profile assumes one pool of funds viewed at 18 and 6 decimals (SPEC-X402-ARC §A.1).\n"+
			"  If that is wrong here, the fee ceiling is meaningless; refusing rather than settling on the assumption", err)
	}
	return dust, nil
}

// BoundNonce reads the nonce to bind, and refuses a gap between the confirmed
// and pending counts. The nonce is the one bound value that comes off the wire,
// so assertion 4 otherwise compares an endpoint-chosen value against itself. A
// hostile or wrong endpoint that returns confirmed+40 gets a valid, signed,
// unexpired payment it can cause to execute whenever it later fills the gap.
func BoundNonce(ctx context.Context, c *ethclient.Client, payer common.Address) (uint64, error) {
	pending, err := c.PendingNonceAt(ctx, payer)
	if err != nil {
		return 0, fmt.Errorf("pending nonce: %w", err)
	}
	confirmed, err := c.NonceAt(ctx, payer, nil)
	if err != nil {
		return 0, fmt.Errorf("confirmed nonce: %w", err)
	}
	if pending != confirmed {
		return 0, fmt.Errorf("endpoint reports pending nonce %d but confirmed nonce %d.\n"+
			"  Either this account has unconfirmed transactions, or the endpoint is choosing when this\n"+
			"  payment executes. A settlement never builds on top of either; wait, or use another endpoint",
			pending, confirmed)
	}
	return pending, nil
}

// ERC20BalanceOf calls balanceOf(address). The selector is derived with the
// audited Keccak rather than hardcoded, because here we have one.
func ERC20BalanceOf(ctx context.Context, c *ethclient.Client, token, holder common.Address) (*big.Int, error) {
	data := make([]byte, 0, 36)
	data = append(data, crypto.Keccak256([]byte("balanceOf(address)"))[:4]...)
	data = append(data, make([]byte, 12)...)
	data = append(data, holder.Bytes()...)

	out, err := c.CallContract(ctx, ethereum.CallMsg{To: &token, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	if len(out) != 32 {
		return nil, fmt.Errorf("balanceOf returned %d bytes, want 32", len(out))
	}
	return new(big.Int).SetBytes(out), nil
}

// USDC renders micro-USDC as a decimal string. Display only.
func USDC(micro *big.Int) string {
	q, r := new(big.Int).QuoRem(micro, big.NewInt(1_000_000), new(big.Int))
	return fmt.Sprintf("%s.%06d", q, r)
}

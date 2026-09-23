//go:build arc

package main

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// runSelfTest builds every adversarial transaction this command can build and
// proves each one is refused for its own reason — offline, with no key file, no
// RPC and no funds. It signs, but only with ephemeral keys generated in memory
// and never with anything on disk, and it broadcasts nothing.
//
// It exists so an operator can watch the controls fire before spending
// anything, and so a demo can be rehearsed without a faucet.
//
// It is a check on the WIRING, not on the guard: settle/evm has its own
// field-flip suite, property test and fuzzers. What this proves is that the
// transactions this command actually constructs reach the guard intact, and
// that the post-sign leg — build, sign with go-ethereum, recover the sender,
// re-check — behaves as specified. That last part is the piece a unit test on
// the guard package cannot see.
func runSelfTest(net evm.ArcNetwork) int {
	const (
		amount   = 1_000_000 // 1.00 USDC
		nonce    = 7
		gasLimit = 60_000
	)
	feeCap := big.NewInt(2_000_000_000)
	maxGasCost := new(big.Int).Mul(big.NewInt(gasLimit), feeCap)

	// An ephemeral payer: a real key so the signing leg is real, generated in
	// memory, never written, worth nothing.
	payerKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("FAIL  could not generate an ephemeral key: %v\n", err)
		return 1
	}
	payer := crypto.PubkeyToAddress(payerKey.PublicKey)
	merchant := common.Address(evm.MustParseAddress("0x2222222222222222222222222222222222222222"))
	asset := common.Address(net.USDC)

	bound, err := newBinding(net, merchant, payer, big.NewInt(amount), nonce, maxGasCost)
	if err != nil {
		fmt.Printf("FAIL  binding: %v\n", err)
		return 1
	}
	signer := newSigner(net)

	base := newPlan(net, merchant, payer, big.NewInt(amount), nonce, feeCap, big.NewInt(1))
	base.gasLimit = gasLimit

	fmt.Println("selftest — SPEC-X402-ARC §A.4, offline, ephemeral key, nothing broadcast")
	fmt.Printf("  network   %s %s (chain id %d)\n", net.Name, net.CAIP2, net.ChainID)
	fmt.Printf("  payer     %s  (ephemeral)\n", payer)
	fmt.Printf("  merchant  %s\n", merchant)
	fmt.Printf("  asset     %s\n", asset)
	fmt.Printf("  amount    %d micro-USDC, nonce %d, fee ceiling %s native units\n\n", amount, nonce, maxGasCost)

	fail := 0
	report := func(name string, err error, want error) {
		switch {
		case want == nil && err == nil:
			fmt.Printf("ok    %-11s  ALLOW\n", name)
		case want == nil:
			fmt.Printf("FAIL  %-11s  the BOUND payment was refused: %v\n", name, err)
			fail++
		case err == nil:
			fmt.Printf("FAIL  %-11s  the guard ALLOWED it — this would have been signed and sent\n", name)
			fail++
		case !errors.Is(err, want):
			// Still refused, so no money moves; but the control that fired is
			// not the one this mode is meant to demonstrate, which means the
			// demo would tell the audience the wrong story.
			fmt.Printf("FAIL  %-11s  refused by the WRONG control: got %v, want %v\n", name, err, want)
			fail++
		default:
			fmt.Printf("ok    %-11s  DENY_VIOLATION — %v\n", name, err)
		}
	}

	// The selector differential, run here too so -selftest is a complete
	// preflight rather than a subset of one.
	if err := assertSelector(); err != nil {
		fmt.Printf("FAIL  %-11s  %v\n", "selector-kat", err)
		fail++
	} else {
		sel := evm.TransferSelector()
		fmt.Printf("ok    %-11s  transfer(address,uint256) → %x, re-derived with an audited Keccak\n", "selector-kat", sel)
	}

	// The honest case, all the way through the signing leg.
	verified, err := evm.Verify(mustView(base, payer), bound)
	report("clean", err, nil)
	if err == nil {
		signed, serr := types.SignTx(base.build(), signer, payerKey)
		if serr != nil {
			fmt.Printf("FAIL  %-11s  sign: %v\n", "clean-signed", serr)
			fail++
		} else {
			sender, rerr := types.Sender(signer, signed)
			if rerr != nil {
				fmt.Printf("FAIL  %-11s  recover sender: %v\n", "clean-signed", rerr)
				fail++
			} else if sender != payer {
				fmt.Printf("FAIL  %-11s  recovered %s, signed with %s\n", "clean-signed", sender, payer)
				fail++
			} else {
				view, verr := viewOf(signed, evm.Address(sender))
				if verr != nil {
					fmt.Printf("FAIL  %-11s  %v\n", "clean-signed", verr)
					fail++
				} else if aerr := verified.AssertSame(view); aerr != nil {
					fmt.Printf("FAIL  %-11s  post-sign re-check rejected an honest signature: %v\n", "clean-signed", aerr)
					fail++
				} else {
					fmt.Printf("ok    %-11s  signed, sender recovered as the payer, every field unchanged\n", "clean-signed")
				}
			}
		}
	}

	for _, name := range sortedModes() {
		mode := tamperModes[name]
		p := base
		p.amount = new(big.Int).Set(base.amount)
		mode.apply(&p)

		if !mode.postSign {
			view, verr := viewOf(p.build(), evm.Address(payer))
			if verr != nil {
				report(name, verr, mode.wantErr)
				continue
			}
			_, gerr := evm.Verify(view, bound)
			report(name, gerr, mode.wantErr)
			continue
		}

		// A post-sign mode: the pre-sign guard MUST pass (that is the point —
		// it cannot see who will sign), and the post-sign re-check must catch
		// it. A mode that the pre-sign guard already refuses proves nothing
		// about the post-sign leg, so that is a failure too.
		view, verr := viewOf(p.build(), evm.Address(payer))
		if verr != nil {
			fmt.Printf("FAIL  %-11s  %v\n", name, verr)
			fail++
			continue
		}
		v, gerr := evm.Verify(view, bound)
		if gerr != nil {
			fmt.Printf("FAIL  %-11s  pre-sign guard refused it (%v) — this mode is meant to be invisible until after signing\n", name, gerr)
			fail++
			continue
		}
		decoy, _ := crypto.GenerateKey()
		signed, serr := types.SignTx(p.build(), signer, decoy)
		if serr != nil {
			fmt.Printf("FAIL  %-11s  sign: %v\n", name, serr)
			fail++
			continue
		}
		sender, rerr := types.Sender(signer, signed)
		if rerr != nil {
			fmt.Printf("FAIL  %-11s  recover sender: %v\n", name, rerr)
			fail++
			continue
		}
		signedView, verr := viewOf(signed, evm.Address(sender))
		if verr != nil {
			fmt.Printf("FAIL  %-11s  %v\n", name, verr)
			fail++
			continue
		}
		report(name, v.AssertSame(signedView), mode.wantErr)
	}

	fmt.Println()
	if fail != 0 {
		fmt.Printf("%d FAILED\n", fail)
		return 1
	}
	fmt.Printf("every control fired as specified; %d modes refused, nothing broadcast\n", len(tamperModes))
	return 0
}

// mustView builds the guard's view of a plan's transaction, treating a read
// failure as a refusal rather than a panic.
func mustView(p plan, signer common.Address) evm.Transaction {
	v, err := viewOf(p.build(), evm.Address(signer))
	if err != nil {
		return evm.Transaction{}
	}
	return v
}

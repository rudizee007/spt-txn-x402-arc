//go:build arc

// Command payarc performs a REAL USDC transfer on Arc testnet, gated by the
// SPT-Txn EVM settle guard (docs/SPEC-X402-ARC.md §A.4). It builds the
// transaction, reads every field back off the object that is about to be
// signed, asserts it moves exactly the bound amount of the bound asset to the
// bound recipient under the bound payer's authority and nothing else, and ONLY
// THEN signs. After signing it recovers the sender from the signature and
// re-checks the whole transaction against what was verified. A pre-sign failure
// means no signature at all; a post-sign failure means the signature exists but
// is never broadcast. Either way no funds move.
//
// SCOPE, stated plainly: the bound payment here is declared by the operator on
// the command line, not consumed from a gate ALLOW. This command demonstrates
// that the settlement path cannot deviate from what it was told to pay — which
// is what the -tamper modes exercise. Wiring it to a live gate decision is the
// mcp-gateway path, not this one. Do not describe its output as proof that an
// authorization was enforced end to end.
//
// This is the one path that touches keys and the network, so it is behind the
// `arc` build tag and excluded from the default `go build ./...` and
// `go test ./...`. The signing key stays in its file; it is never read from an
// environment variable, never printed, and never committed.
//
// Build and run (cgo MUST be off — see nocgo.go):
//
//	go get github.com/ethereum/go-ethereum
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -selftest          # offline, no key, no funds
//	# fund your Arc testnet wallet with USDC: https://faucet.circle.com
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc https://rpc.testnet.arc.io -amount 100000
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc ... -to 0x… -amount 100000
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc ... -tamper value   # guard refuses to sign
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -tamper list             # every adversarial mode
//
// Nothing here is externally audited and nothing is in production.
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// nativePerMicroUSDC is the ratio between USDC's native view (18 decimals) and
// its ERC-20 view (6 decimals) on Arc. It applies ONLY to the fee ceiling —
// never to a payment amount — and it is exact integer arithmetic.
//
// §A.5.11 says the settlement path never converts between the two views, and
// a ceiling expressed in the same unit as -amount is a deliberate, narrow
// exception so an operator does not have to type 1e18-scale numbers. The
// exception is only safe because the ratio is CHECKED at run time against the
// chain rather than assumed: see assertNativeRatio. An unchecked constant here
// would silently multiply the ceiling by 10^12 if Arc's native view were not 18
// decimals, which would disable §A.4 assertion 7 while still printing PASS.
var nativePerMicroUSDC = new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil)

const (
	// confirmTimeout bounds how long we wait for inclusion before reporting
	// DENY_UNAVAILABLE. A transaction that is broadcast but unconfirmed is an
	// unknown, not a success.
	confirmTimeout = 3 * time.Minute

	// maxGasLimit is a sanity bound on the RPC's gas estimate. An ERC-20
	// transfer costs tens of thousands of gas; anything near this is either a
	// hostile endpoint or a transaction we did not mean to send. It also stops
	// the headroom arithmetic below from overflowing a uint64 on a wire value.
	maxGasLimit = 10_000_000
)

func defaultKeyPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		// Not a warning: an empty home turns the default into a RELATIVE path
		// resolved against the working directory, so a settlement could read a
		// key from wherever it happened to be started.
		return "", fmt.Errorf("cannot determine the home directory (%v); pass -key explicitly", err)
	}
	return filepath.Join(h, ".config", "spt-txn", "arc.key"), nil
}

func main() {
	defaultKey, keyPathErr := defaultKeyPath()

	rpcURL := flag.String("rpc", "", "Arc testnet JSON-RPC endpoint (REQUIRED; public sources disagree — see SPEC-X402-ARC §A.1)")
	keyPath := flag.String("key", defaultKey, "path to a file containing the payer's secp256k1 key as 64 hex characters")
	toStr := flag.String("to", "", "merchant address (0x…); default: pay yourself")
	boundPayTo := flag.String("bound-payto", "", "the payTo identifier as the gate carries it (base58 of the 32-byte account id); when set, it must denote -to")
	amount := flag.Uint64("amount", 100_000, "amount in micro-USDC (100000 = 0.10 USDC)")
	maxFee := flag.Uint64("max-fee", 50_000, "ceiling on the total transaction fee, in micro-USDC")
	tamper := flag.String("tamper", "", "adversarial demo: build a transaction that trips one §A.4 assertion; `-tamper list` shows them")
	dryRun := flag.Bool("dry-run", false, "build and assert, but never sign or broadcast")
	selfTest := flag.Bool("selftest", false, "offline: build every adversarial transaction and prove each trips its own §A.4 assertion. No key, no network, no funds")
	flag.Parse()

	if *tamper == "list" {
		printTamperModes()
		return
	}
	if *selfTest {
		os.Exit(runSelfTest())
	}
	if *rpcURL == "" {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("-rpc is required and has no default.\n"+
			"  Arc's own docs publish   https://rpc.testnet.arc.io\n"+
			"  Circle's use-arc skill publishes  https://rpc.testnet.arc.network\n"+
			"  They disagree. Confirm the live one and pass it explicitly rather than\n"+
			"  letting a settlement path silently choose a network endpoint for you"))
	}
	if *keyPath == "" {
		fatal("DENY_UNAVAILABLE", keyPathErr)
	}
	var mode tamperMode
	if *tamper != "" {
		m, ok := tamperModes[*tamper]
		if !ok {
			fatal("DENY_VIOLATION", fmt.Errorf("unknown -tamper mode %q; run with `-tamper list`", *tamper))
		}
		mode = m
	}

	ctx, cancel := context.WithTimeout(context.Background(), confirmTimeout+time.Minute)
	defer cancel()

	// ── 0. Differential check on the one hardcoded constant ────────────────
	//
	// settle/evm hardcodes the ERC-20 transfer selector because it computes no
	// Keccak. This binary links an audited Keccak, so it recomputes the
	// selector and refuses to run on disagreement (§A.3). A hardcoded constant
	// that nothing checks is not acceptable; one that an audited implementation
	// re-derives on every run is.
	if err := assertSelector(); err != nil {
		fatal("DENY_VIOLATION", err)
	}

	// ── 1. Key and payer identity ──────────────────────────────────────────
	key := loadKey(*keyPath)
	payer := crypto.PubkeyToAddress(key.PublicKey)

	// ── 2. Recipient ───────────────────────────────────────────────────────
	merchant := payer
	if *toStr != "" {
		a, err := evm.ParseAddress(*toStr)
		if err != nil {
			fatal("DENY_VIOLATION", fmt.Errorf("bad -to address: %w", err))
		}
		merchant = common.Address(a)
	}

	asset := common.Address(evm.USDCArcTestnet)

	fmt.Printf("network:   %s (chain id %d)\n", evm.ArcTestnetCAIP2, evm.ArcTestnetChainID)
	fmt.Printf("rpc:       %s\n", *rpcURL)
	fmt.Printf("payer:     %s\n", payer)
	fmt.Printf("merchant:  %s\n", merchant)
	fmt.Printf("asset:     %s  (USDC, %d decimals in the ERC-20 view)\n", asset, evm.USDCDecimals)
	fmt.Printf("amount:    %d micro-USDC (%s USDC)\n", *amount, usdc(new(big.Int).SetUint64(*amount)))
	fmt.Printf("fee cap:   %d micro-USDC\n", *maxFee)

	// The identifier the gate binds is base58 of the widened 32-byte account id
	// (§A.2). If the operator supplies the one the gate actually carried, it is
	// checked against the address we are about to pay — two independent sides,
	// a comparison that can fail. Without it, we only print the encoding: a
	// value compared against itself is not a control, and printing it as though
	// it were is worse than not checking at all.
	transport := evm.AccountIDBase58(evm.Address(merchant))
	if *boundPayTo != "" {
		if err := evm.AssertTransportMatches(evm.Address(merchant), *boundPayTo); err != nil {
			fatal("DENY_VIOLATION", fmt.Errorf("-bound-payto does not denote -to (%s): %w", merchant, err))
		}
		fmt.Printf("bound payTo: %s  (matches -to)\n\n", *boundPayTo)
	} else {
		fmt.Printf("payTo as the gate would carry it: %s  (not checked — pass -bound-payto to check it)\n\n", transport)
	}

	// ── 3. Connect, and refuse to adopt anything from the wire ─────────────
	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("dial %s: %w", *rpcURL, err))
	}
	defer client.Close()

	reported, err := client.ChainID(ctx)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("eth_chainId: %w", err))
	}
	// §A.5.12: the bound chain id is configuration. A disagreeing endpoint is
	// refused, never adopted.
	if !reported.IsUint64() || reported.Uint64() != evm.ArcTestnetChainID {
		fatal("DENY_VIOLATION", fmt.Errorf("endpoint reports chain id %s, this profile is bound to %d — refusing to settle on an unexpected network", reported, evm.ArcTestnetChainID))
	}

	// ── 4. Preflight: does the payer hold the USDC, and is the fee ceiling
	//      denominated in what we think it is? ──────────────────────────────
	bal, err := erc20BalanceOf(ctx, client, asset, payer)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("balanceOf(%s): %w\n  -> is %s the right USDC contract on this endpoint?", payer, err, asset))
	}
	fmt.Printf("balance:   %s micro-USDC (%s USDC)\n", bal, usdc(bal))
	if bal.Cmp(new(big.Int).SetUint64(*amount)) < 0 || bal.Sign() == 0 {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("insufficient USDC: have %s, need %d micro-USDC\n  -> top up %s at %s (select Arc testnet)", bal, *amount, payer, evm.USDCFaucet))
	}
	if err := assertNativeRatio(ctx, client, payer, bal); err != nil {
		fatal("DENY_VIOLATION", err)
	}

	// ── 5. Nonce and fees ──────────────────────────────────────────────────
	nonce, err := boundNonce(ctx, client, payer)
	if err != nil {
		fatal("DENY_VIOLATION", err)
	}
	tip, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("suggest gas tip: %w", err))
	}
	head, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("latest header: %w", err))
	}
	if head.BaseFee == nil {
		fatal("DENY_UNAVAILABLE", errors.New("latest header carries no base fee — this endpoint does not look EIP-1559"))
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	maxGasCost := new(big.Int).Mul(new(big.Int).SetUint64(*maxFee), nativePerMicroUSDC)

	p := plan{
		asset: asset, merchant: merchant, payer: payer,
		amount: new(big.Int).SetUint64(*amount), nonce: nonce,
		feeCap: feeCap, tip: tip,
	}
	if mode.apply != nil {
		fmt.Printf("\n[tamper %s] %s\n", *tamper, mode.description)
		mode.apply(&p)
	}

	// Estimate gas against the payload we are actually going to send.
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From: payer, To: p.txTo(), Value: p.value(), Data: p.calldata(),
	})
	if err != nil {
		// A tampered payload may well be un-estimatable. That is fine: the
		// guard, not the RPC, is what must refuse it, so fall back to a fixed
		// limit and let the assertion do its job.
		gasLimit = 100_000
		fmt.Printf("note:      gas estimation failed (%v); using %d so the guard still runs\n", err, gasLimit)
	} else {
		if gasLimit > maxGasLimit {
			fatal("DENY_VIOLATION", fmt.Errorf("endpoint estimated %d gas for an ERC-20 transfer (bound %d) — refusing", gasLimit, maxGasLimit))
		}
		gasLimit += gasLimit / 5 // 20% headroom; cannot overflow, gasLimit ≤ maxGasLimit
	}
	p.gasLimit = gasLimit

	fmt.Printf("\ngas limit: %d\n", gasLimit)
	fmt.Printf("fee cap:   %s per gas (base %s + tip %s)\n", feeCap, head.BaseFee, tip)
	fmt.Printf("worst-case fee: %s of %s native units\n", new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), feeCap), maxGasCost)

	bound, err := evm.NewBoundPayment(evm.Binding{
		ChainID:    evm.ArcTestnetChainID,
		Asset:      evm.Address(asset).AccountID32(),
		PayTo:      evm.Address(merchant).AccountID32(),
		Payer:      evm.Address(payer).AccountID32(),
		Amount:     new(big.Int).SetUint64(*amount),
		Nonce:      nonce,
		MaxGasCost: maxGasCost,
	})
	if err != nil {
		fatal("DENY_VIOLATION", fmt.Errorf("binding: %w", err))
	}

	// ── 6. Build the signer FIRST ──────────────────────────────────────────
	//
	// go-ethereum hashes the SIGNER's chain id into the signing preimage and
	// overwrites the transaction's own ChainID field with it, so the field the
	// guard asserts is not by itself the field that enters the signature.
	// Constructing the signer before the guard runs, and pinning its chain id
	// to the same constant, means assertion 3 and the preimage cannot drift.
	signer := types.LatestSignerForChainID(new(big.Int).SetUint64(evm.ArcTestnetChainID))
	if sc := signer.ChainID(); !sc.IsUint64() || sc.Uint64() != bound.ChainID() {
		fatal("DENY_VIOLATION", fmt.Errorf("signer chain id %s != bound chain id %d", sc, bound.ChainID()))
	}

	// ── 7. Build the transaction, then read it BACK off the object ─────────
	tx := p.build()
	view, err := viewOf(tx, evm.Address(payer))
	if err != nil {
		fatal("DENY_VIOLATION", err)
	}

	// ── 8. §A.4 pre-sign gate ──────────────────────────────────────────────
	verified, err := evm.Verify(view, bound)
	if err != nil {
		fmt.Println()
		fatal("DENY_VIOLATION", fmt.Errorf("REFUSING TO SIGN — the settle guard rejected the transaction: %w\n"+
			"  Nothing was signed. Nothing was broadcast. No funds moved.", err))
	}
	fmt.Printf("\nguard:     PASS — the transaction matches the payment this command was told to make\n")

	if *dryRun {
		fmt.Println("dry run:   stopping before the signature, as asked.")
		return
	}

	// ── 9. Sign with the payer's key, then re-check ────────────────────────
	signKey := key
	if p.decoyKey {
		k, err := crypto.GenerateKey()
		if err != nil {
			fatal("DENY_UNAVAILABLE", fmt.Errorf("generate decoy key: %w", err))
		}
		signKey = k
		fmt.Printf("[tamper]   signing with an unauthorized ephemeral key %s\n", crypto.PubkeyToAddress(k.PublicKey))
	}
	signed, err := types.SignTx(tx, signer, signKey)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("sign: %w", err))
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		fatal("DENY_VIOLATION", fmt.Errorf("cannot recover the sender from the signature: %w", err))
	}
	signedView, err := viewOf(signed, evm.Address(sender))
	if err != nil {
		fatal("DENY_VIOLATION", err)
	}
	if err := verified.AssertSame(signedView); err != nil {
		fatal("DENY_VIOLATION", fmt.Errorf("REFUSING TO BROADCAST — the signed transaction is not the one that was verified: %w\n"+
			"  A signature exists in memory and is being discarded. Nothing was broadcast. No funds moved.", err))
	}
	fmt.Printf("post-sign: PASS — recovered sender %s matches, every field unchanged\n", sender)

	// ── 10. Broadcast and confirm ──────────────────────────────────────────
	if err := client.SendTransaction(ctx, signed); err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("broadcast: %w", err))
	}
	fmt.Printf("\nsent:      %s%s\n", evm.ArcTestnetExplorerTxPrefix, signed.Hash().Hex())

	waitCtx, waitCancel := context.WithTimeout(ctx, confirmTimeout)
	defer waitCancel()
	receipt, err := bind.WaitMined(waitCtx, client, signed)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("broadcast but NOT confirmed within %s: %w\n  The transaction may still land. Check the explorer link above before retrying.", confirmTimeout, err))
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("transaction reverted on chain (status %d, gas used %d)", receipt.Status, receipt.GasUsed))
	}

	fmt.Printf("\nSETTLED    %d micro-USDC (%s USDC)\n", *amount, usdc(new(big.Int).SetUint64(*amount)))
	fmt.Printf("  payer:    %s\n", payer)
	fmt.Printf("  merchant: %s\n", merchant)
	fmt.Printf("  block:    %d, gas used %d\n", receipt.BlockNumber, receipt.GasUsed)
	fmt.Printf("  tx:       %s%s\n", evm.ArcTestnetExplorerTxPrefix, signed.Hash().Hex())
}

// ── preflight assertions ────────────────────────────────────────────────────

func assertSelector() error {
	want := crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
	got := evm.TransferSelector()
	if string(want) != string(got[:]) {
		return fmt.Errorf("selector differential FAILED: keccak256(\"transfer(address,uint256)\")[:4] = %x, settle/evm has %x", want, got)
	}
	return nil
}

// assertNativeRatio checks the 18-vs-6 decimal assumption against the chain
// instead of trusting it. On Arc the native balance and the ERC-20 balance are
// two views of THE SAME funds, so they must differ by exactly 10^12. If they do
// not, the fee ceiling is denominated in something other than what we think and
// §A.4 assertion 7 would be off by twelve orders of magnitude — while still
// printing PASS. That is the failure a constant with no check produces.
func assertNativeRatio(ctx context.Context, c *ethclient.Client, payer common.Address, erc20 *big.Int) error {
	native, err := c.BalanceAt(ctx, payer, nil)
	if err != nil {
		return fmt.Errorf("native balance: %w", err)
	}
	want := new(big.Int).Mul(erc20, nativePerMicroUSDC)
	if native.Cmp(want) != 0 {
		return fmt.Errorf("the native and ERC-20 views of USDC disagree: native %s, erc20 %s × 10^12 = %s.\n"+
			"  This profile assumes one pool of funds at 18 and 6 decimals (SPEC-X402-ARC §A.1).\n"+
			"  If that is wrong here, the fee ceiling is meaningless — refusing rather than settling on the assumption",
			native, erc20, want)
	}
	fmt.Printf("decimals:  native/ERC-20 ratio confirmed at 10^12 against the chain\n")
	return nil
}

// boundNonce reads the nonce to bind, and refuses a gap between the confirmed
// and pending counts. The nonce is the one bound value that comes off the wire,
// so assertion 4 otherwise compares an endpoint-chosen value against itself. A
// hostile or wrong endpoint that returns confirmed+40 gets a valid, signed,
// unexpired payment it can cause to execute whenever it later fills the gap —
// which would hand away exactly the short-lived authority the token model
// exists to keep.
func boundNonce(ctx context.Context, c *ethclient.Client, payer common.Address) (uint64, error) {
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
			"  payment executes. A settlement never builds on top of either — wait, or use another endpoint",
			pending, confirmed)
	}
	return pending, nil
}

// ── the transaction plan ────────────────────────────────────────────────────

// plan holds everything the transaction is built from, so a tamper mode can
// change exactly one thing and the build path stays identical otherwise. The
// guard then sees whatever this produced — it is never told what was intended.
type plan struct {
	asset    common.Address
	merchant common.Address
	payer    common.Address
	amount   *big.Int
	nonce    uint64
	gasLimit uint64
	feeCap   *big.Int
	tip      *big.Int

	// tamper knobs
	legacy      bool
	chainID     *big.Int
	nativeValue *big.Int
	toOverride  *common.Address
	dataOverlay func([]byte) []byte
	accessList  types.AccessList
	decoyKey    bool // sign with an unauthorized key: a POST-sign mode
}

func (p plan) chain() *big.Int {
	if p.chainID != nil {
		return p.chainID
	}
	return new(big.Int).SetUint64(evm.ArcTestnetChainID)
}

func (p plan) value() *big.Int {
	if p.nativeValue != nil {
		return p.nativeValue
	}
	return big.NewInt(0)
}

func (p plan) txTo() *common.Address {
	if p.toOverride != nil {
		return p.toOverride
	}
	a := p.asset
	return &a
}

func (p plan) calldata() []byte {
	data, err := evm.EncodeTransfer(evm.Address(p.merchant), p.amount)
	if err != nil {
		fatal("DENY_VIOLATION", fmt.Errorf("encode transfer: %w", err))
	}
	if p.dataOverlay != nil {
		return p.dataOverlay(data)
	}
	return data
}

func (p plan) build() *types.Transaction {
	if p.legacy {
		return types.NewTx(&types.LegacyTx{
			Nonce: p.nonce, GasPrice: p.feeCap, Gas: p.gasLimit,
			To: p.txTo(), Value: p.value(), Data: p.calldata(),
		})
	}
	return types.NewTx(&types.DynamicFeeTx{
		ChainID: p.chain(), Nonce: p.nonce,
		GasTipCap: p.tip, GasFeeCap: p.feeCap, Gas: p.gasLimit,
		To: p.txTo(), Value: p.value(), Data: p.calldata(),
		AccessList: p.accessList,
	})
}

// viewOf reads the guard's view off the real transaction object — every field
// from an accessor, none from what we meant to build. That is what makes the
// assertion an assertion about the thing that will be signed rather than about
// a parallel copy of our intentions.
func viewOf(tx *types.Transaction, signer evm.Address) (evm.Transaction, error) {
	var to *evm.Address
	if t := tx.To(); t != nil {
		a := evm.Address(*t)
		to = &a
	}
	chainID := tx.ChainId()
	// Never nil in go-ethereum. This catches a chain id past 2^64; an
	// unprotected legacy transaction derives a large nonsense chain id from
	// V and is refused by §A.4 assertion 1 on the type, not here.
	if chainID == nil || !chainID.IsUint64() {
		return evm.Transaction{}, fmt.Errorf("transaction carries an unusable chain id %v", chainID)
	}
	return evm.Transaction{
		Type:                 tx.Type(),
		ChainID:              chainID.Uint64(),
		Nonce:                tx.Nonce(),
		GasLimit:             tx.Gas(),
		MaxFeePerGas:         tx.GasFeeCap(),
		To:                   to,
		Value:                tx.Value(),
		Data:                 tx.Data(),
		AccessListLen:        len(tx.AccessList()),
		AuthorizationListLen: len(tx.SetCodeAuthorizations()),
		BlobHashLen:          len(tx.BlobHashes()),
		Signer:               signer,
	}, nil
}

// ── adversarial demo modes ──────────────────────────────────────────────────

type tamperMode struct {
	description string
	// wantErr is the sentinel this mode must trip. It lives here so the mapping
	// from "what the attacker did" to "which control caught it" is written down
	// once and checked by -selftest, rather than asserted in prose.
	wantErr error
	// postSign marks a mode the pre-sign guard cannot see, because it changes
	// who signs rather than what is signed.
	postSign bool
	apply    func(*plan)
}

// Every mode trips exactly one assertion, so the demo can show each control
// firing on its own rather than one generic refusal.
var tamperModes = map[string]tamperMode{
	"recipient": {"building the transfer to an ATTACKER address while the bound payTo is the merchant (§A.4.11)",
		evm.ErrDestinationMismatch, false, func(p *plan) {
			p.merchant = common.Address(evm.MustParseAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"))
		}},
	"amount": {"inflating the transfer 1000× above the bound amount (§A.4.12)",
		evm.ErrAmountMismatch, false, func(p *plan) {
			p.amount = new(big.Int).Mul(p.amount, big.NewInt(1000))
		}},
	"value": {"attaching NATIVE USDC to a perfectly bound ERC-20 payload — same funds, second interface (§A.4.6, §A.5.1)",
		evm.ErrNonZeroValue, false, func(p *plan) {
			p.nativeValue = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 1 USDC, natively
		}},
	"chain": {"building for Ethereum mainnet instead of Arc (§A.4.3)",
		evm.ErrChainIDMismatch, false, func(p *plan) {
			p.chainID = big.NewInt(1)
		}},
	"nonce": {"reusing the authorization on a second nonce (§A.4.4)",
		evm.ErrNonceMismatch, false, func(p *plan) {
			p.nonce = p.nonce + 1
		}},
	"target": {"routing the call through Arc's Multicall3From instead of the USDC contract (§A.4.5)",
		evm.ErrAssetMismatch, false, func(p *plan) {
			a := common.Address(evm.MustParseAddress("0x522fAf9A91c41c443c66765030741e4AaCe147D0"))
			p.toOverride = &a
		}},
	"selector": {"swapping transfer() for approve() — a standing allowance instead of a payment (§A.4.10)",
		evm.ErrNotTransfer, false, func(p *plan) {
			p.dataOverlay = func(d []byte) []byte {
				out := append([]byte(nil), d...)
				copy(out[:4], []byte{0x09, 0x5e, 0xa7, 0xb3})
				return out
			}
		}},
	"tail": {"appending bytes after the ABI arguments, which Solidity would ignore (§A.4.9)",
		evm.ErrCalldataLength, false, func(p *plan) {
			p.dataOverlay = func(d []byte) []byte { return append(append([]byte(nil), d...), 0xde, 0xad, 0xbe, 0xef) }
		}},
	"padding": {"dirtying the ignored high bytes of the address word (§A.4.10)",
		evm.ErrDirtyAddressWord, false, func(p *plan) {
			p.dataOverlay = func(d []byte) []byte {
				out := append([]byte(nil), d...)
				out[4] = 0xff
				return out
			}
		}},
	"gas": {"raising the fee cap so the FEE dwarfs the payment — in the same asset (§A.4.7, §A.5.3)",
		evm.ErrGasCeilingExceeded, false, func(p *plan) {
			p.feeCap = new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)
		}},
	"accesslist": {"attaching an EIP-2930 access list the binding never authorized (§A.4.2)",
		evm.ErrAccessListPresent, false, func(p *plan) {
			p.accessList = types.AccessList{{Address: p.asset, StorageKeys: []common.Hash{{}}}}
		}},
	"legacy": {"downgrading to a pre-EIP-1559 legacy transaction envelope (§A.4.1)",
		evm.ErrUnsupportedTxType, false, func(p *plan) {
			p.legacy = true
		}},
	"signer": {"signing a perfectly bound transaction with an unauthorized key — invisible before signing, caught after (§A.4 post-sign)",
		evm.ErrPostSignDivergence, true, func(p *plan) {
			p.decoyKey = true
		}},
}

func printTamperModes() {
	fmt.Println("adversarial demo modes — each trips exactly one assertion:")
	for _, n := range sortedModes() {
		leg := "pre-sign "
		if tamperModes[n].postSign {
			leg = "post-sign"
		}
		fmt.Printf("  -tamper %-11s [%s] %s\n", n, leg, tamperModes[n].description)
	}
}

func sortedModes() []string {
	names := make([]string, 0, len(tamperModes))
	for n := range tamperModes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ── helpers ─────────────────────────────────────────────────────────────────

// erc20BalanceOf calls balanceOf(address). The selector is derived with the
// audited Keccak rather than hardcoded, because here we have one.
func erc20BalanceOf(ctx context.Context, c *ethclient.Client, token, holder common.Address) (*big.Int, error) {
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

// loadKey reads the payer's key from a file and refuses a file anyone else can
// read. The key never enters an environment variable and is never printed.
func loadKey(path string) *ecdsa.PrivateKey {
	// Lstat, not Stat: a symlink's target mode is not the thing an attacker
	// would have to change to substitute a key.
	info, err := os.Lstat(path)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("no key file at %s: %w\n"+
			"  Create one with 64 hex characters (no 0x) and chmod 600:\n"+
			"    mkdir -p %s && (umask 077 && openssl rand -hex 32 > %s)", path, err, filepath.Dir(path), path))
	}
	if !info.Mode().IsRegular() {
		fatal("DENY_VIOLATION", fmt.Errorf("key path %s is not a regular file (mode %v)", path, info.Mode()))
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		fatal("DENY_VIOLATION", fmt.Errorf("key file %s is mode %04o — group- or world-readable.\n  chmod 600 %s", path, mode, path))
	}
	if dir, err := os.Stat(filepath.Dir(path)); err == nil && dir.Mode().Perm()&0o022 != 0 {
		fatal("DENY_VIOLATION", fmt.Errorf("directory %s is mode %04o — group- or world-WRITABLE, so the key file can be replaced.\n  chmod 700 %s", filepath.Dir(path), dir.Mode().Perm(), filepath.Dir(path)))
	}
	key, err := crypto.LoadECDSA(path)
	if err != nil {
		fatal("DENY_UNAVAILABLE", fmt.Errorf("read key from %s: %w (want exactly 64 hex characters, no 0x prefix)", path, err))
	}
	return key
}

// usdc renders micro-USDC as a decimal string. Display only.
func usdc(micro *big.Int) string {
	q, r := new(big.Int).QuoRem(micro, big.NewInt(1_000_000), new(big.Int))
	return fmt.Sprintf("%s.%06d", q, r)
}

// fatal prints the decision class the operator needs — an attack looks
// different from an outage (SPEC-X402 §5) — and exits non-zero.
func fatal(class string, err error) {
	fmt.Fprintf(os.Stderr, "\n%s: %s\n", class, strings.TrimSpace(err.Error()))
	os.Exit(1)
}

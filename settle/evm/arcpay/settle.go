//go:build arc

package arcpay

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// Decision classes. Every error Settle returns wraps exactly one of them, so an
// operator can tell an attack from an outage (SPEC-X402 §5).
var (
	ErrViolation   = errors.New("DENY_VIOLATION")
	ErrUnavailable = errors.New("DENY_UNAVAILABLE")
)

func violation(err error) error   { return fmt.Errorf("%w: %w", ErrViolation, err) }
func unavailable(err error) error { return fmt.Errorf("%w: %w", ErrUnavailable, err) }

// Input errors, each wrapped in ErrViolation.
var (
	ErrNotAuthorized  = errors.New("arcpay: no authorization marker; nothing is settled without one")
	ErrAssetNotUSDC   = errors.New("arcpay: authorized asset is not the selected network's USDC")
	ErrBadAmount      = errors.New("arcpay: authorized amount is not a positive base-10 integer")
	ErrZeroRecipient  = errors.New("arcpay: recipient is the zero address")
	ErrMissingConfig  = errors.New("arcpay: settlement configuration is incomplete")
	ErrUnboundedGas   = errors.New("arcpay: endpoint gas estimate exceeds the sanity bound")
	ErrSignerMismatch = errors.New("arcpay: signer chain id differs from the bound chain id")
	ErrExpired        = errors.New("arcpay: the authorization expired before the payment was signed")
	ErrNonceDisagrees = errors.New("arcpay: the nonce-check endpoint disagrees with the settlement endpoint")
)

const (
	// DefaultConfirmTimeout bounds how long Settle waits for inclusion. A
	// transaction broadcast but unconfirmed is an unknown, not a success.
	DefaultConfirmTimeout = 3 * time.Minute

	// MaxGasLimit is a sanity bound on the endpoint's gas estimate. An ERC-20
	// transfer costs tens of thousands of gas; anything near this is a hostile
	// endpoint or a transaction we did not mean to send. It also keeps the
	// headroom arithmetic below from overflowing a uint64.
	MaxGasLimit = 10_000_000
)

// Payment is an already-authorized payment. Every field comes from the
// enforcement point's authorized decision, except Recipient, which is the one
// address the human approved; Settle proves the two agree (SPEC-ARC-GATE §4).
type Payment struct {
	// Authorization is the ALLOW's transparency-log locator. Empty is refused.
	Authorization string
	// Recipient is the approved recipient address.
	Recipient evm.Address
	// PayToTransport and AssetTransport are the authorized call's recipient and
	// asset, in the §A.2 transport form (base58 of the 32-byte account id).
	PayToTransport string
	AssetTransport string
	// AmountMicro is the authorized amount, micro-USDC, as a base-10 string.
	AmountMicro string
	// NotAfter is the authorization's expiry. Everything before signing runs
	// under this deadline, and it is checked again immediately before the
	// signature, so a slow or hostile endpoint cannot choose to have the
	// payment signed after the authorization has lapsed. Zero is refused.
	NotAfter time.Time
}

// Config is everything Settle needs that is not part of the payment.
type Config struct {
	Net            evm.ArcNetwork
	Client         *ethclient.Client
	Key            *ecdsa.PrivateKey
	MaxFeeMicro    uint64        // ceiling on the whole fee, micro-USDC
	ConfirmTimeout time.Duration // 0 means DefaultConfirmTimeout
	Log            io.Writer     // progress lines; nil means discard
	// NonceCheck, if set, is a second, independent endpoint. The confirmed
	// nonce must agree on both, so one hostile endpoint cannot bind a future
	// nonce on its own (see BoundNonce).
	NonceCheck *ethclient.Client
	Now        func() time.Time // injectable for tests; defaults to time.Now
}

// Result describes a settled payment.
type Result struct {
	TxHash  common.Hash
	Block   uint64
	GasUsed uint64
	Payer   common.Address
}

// Demo holds cmd/payarc's demonstration hooks. Settle never sets it; only
// SettleWithDemo takes one. None of these can make the guard accept a payment
// it would otherwise refuse: they change what is built or who signs, and the
// guard sees the result.
type Demo struct {
	DryRun   bool              // stop after the pre-sign guard passes
	Tamper   func(*Plan)       // change exactly one thing about the plan
	DecoyKey *ecdsa.PrivateKey // sign with this key instead (post-sign mode)
	Label    string            // printed with the tamper description
}

// Settle pays an authorized payment on Arc through the pre-sign guard.
func Settle(ctx context.Context, cfg Config, p Payment) (Result, error) {
	return run(ctx, cfg, p, Demo{})
}

// SettleWithDemo is Settle with cmd/payarc's demonstration hooks.
func SettleWithDemo(ctx context.Context, cfg Config, p Payment, d Demo) (Result, error) {
	return run(ctx, cfg, p, d)
}

// ParseAtomic parses an authorized micro-USDC amount: base-10 digits only, no
// sign, no leading zero, no overflow, not zero.
func ParseAtomic(s string) (*big.Int, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return nil, violation(ErrBadAmount)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return nil, violation(ErrBadAmount)
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return nil, violation(ErrBadAmount)
	}
	return new(big.Int).SetUint64(v), nil
}

// checkPayment performs every check on the payment that needs no network, key
// or endpoint. It runs before any of those are touched (SPEC-ARC-GATE I2).
func checkPayment(net evm.ArcNetwork, p Payment) (*big.Int, error) {
	if p.Authorization == "" {
		return nil, violation(ErrNotAuthorized)
	}
	if p.NotAfter.IsZero() {
		return nil, violation(fmt.Errorf("%w: no expiry on the authorization", ErrNotAuthorized))
	}
	if p.Recipient.IsZero() {
		return nil, violation(ErrZeroRecipient)
	}
	// Re-encode and compare; there is deliberately no base58 decoder in this
	// repository (settle/evm/binding.go).
	if err := evm.AssertTransportMatches(p.Recipient, p.PayToTransport); err != nil {
		return nil, violation(err)
	}
	want := evm.AccountIDBase58(net.USDC)
	if subtle.ConstantTimeCompare([]byte(want), []byte(p.AssetTransport)) != 1 {
		return nil, violation(ErrAssetNotUSDC)
	}
	return ParseAtomic(p.AmountMicro)
}

func run(ctx context.Context, cfg Config, p Payment, d Demo) (Result, error) {
	out := cfg.Log
	if out == nil {
		out = io.Discard
	}
	amount, err := checkPayment(cfg.Net, p)
	if err != nil {
		return Result{}, err
	}
	if cfg.Client == nil || cfg.Key == nil || cfg.Net.ChainID == 0 {
		return Result{}, unavailable(ErrMissingConfig)
	}
	if cfg.MaxFeeMicro == 0 {
		return Result{}, violation(fmt.Errorf("%w: zero fee ceiling", ErrMissingConfig))
	}
	confirm := cfg.ConfirmTimeout
	if confirm <= 0 {
		confirm = DefaultConfirmTimeout
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	if !now().Before(p.NotAfter) {
		return Result{}, violation(ErrExpired)
	}
	// Everything up to the signature runs under the authorization's deadline.
	// Confirmation afterwards uses the caller's context: once broadcast, the
	// transaction's fate no longer depends on this process.
	parent := ctx
	ctx, cancelPre := context.WithDeadline(ctx, p.NotAfter)
	defer cancelPre()

	// ── 0. Differential check on the one hardcoded constant ────────────────
	if err := AssertSelector(); err != nil {
		return Result{}, violation(err)
	}

	payer := crypto.PubkeyToAddress(cfg.Key.PublicKey)
	merchant := common.Address(p.Recipient)
	asset := common.Address(cfg.Net.USDC)

	// ── 1. Refuse to adopt anything from the wire ──────────────────────────
	reported, err := cfg.Client.ChainID(ctx)
	if err != nil {
		return Result{}, unavailable(fmt.Errorf("eth_chainId: %w", err))
	}
	// §A.5.12: the bound chain id is configuration. A disagreeing endpoint is
	// refused, never adopted.
	if err := CheckEndpointChain(cfg.Net, reported); err != nil {
		return Result{}, violation(err)
	}

	// ── 2. Preflight: funds, and the unit the fee ceiling is in ────────────
	bal, err := ERC20BalanceOf(ctx, cfg.Client, asset, payer)
	if err != nil {
		return Result{}, unavailable(fmt.Errorf("balanceOf(%s): %w", payer, err))
	}
	fmt.Fprintf(out, "balance:   %s micro-USDC (%s USDC)\n", bal, USDC(bal))
	if bal.Cmp(amount) < 0 || bal.Sign() == 0 {
		return Result{}, unavailable(fmt.Errorf("insufficient USDC: have %s, need %s micro-USDC in %s", bal, amount, payer))
	}
	dust, err := AssertNativeRatio(ctx, cfg.Client, payer, bal)
	if err != nil {
		return Result{}, violation(err)
	}
	fmt.Fprintf(out, "decimals:  native/ERC-20 relation confirmed against the chain (10^12, residue %s native units)\n", dust)

	// ── 3. Nonce and fees ──────────────────────────────────────────────────
	nonce, err := BoundNonce(ctx, cfg.Client, payer)
	if err != nil {
		return Result{}, violation(err)
	}
	if cfg.NonceCheck != nil {
		other, err := cfg.NonceCheck.NonceAt(ctx, payer, nil)
		if err != nil {
			return Result{}, unavailable(fmt.Errorf("nonce-check endpoint: %w", err))
		}
		if other != nonce {
			return Result{}, violation(fmt.Errorf("%w: %d vs %d", ErrNonceDisagrees, nonce, other))
		}
	}
	tip, err := cfg.Client.SuggestGasTipCap(ctx)
	if err != nil {
		return Result{}, unavailable(fmt.Errorf("suggest gas tip: %w", err))
	}
	head, err := cfg.Client.HeaderByNumber(ctx, nil)
	if err != nil {
		return Result{}, unavailable(fmt.Errorf("latest header: %w", err))
	}
	if head.BaseFee == nil {
		return Result{}, unavailable(errors.New("latest header carries no base fee; this endpoint does not look EIP-1559"))
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	maxGasCost := new(big.Int).Mul(new(big.Int).SetUint64(cfg.MaxFeeMicro), evm.NativeScale())

	plan := NewPlan(cfg.Net, merchant, payer, amount, nonce, feeCap, tip)
	if d.Tamper != nil {
		fmt.Fprintf(out, "\n[tamper] %s\n", d.Label)
		d.Tamper(&plan)
	}

	// ── 4. Gas, estimated against the payload we will actually send ────────
	data, err := plan.Calldata()
	if err != nil {
		return Result{}, violation(err)
	}
	gasLimit, err := cfg.Client.EstimateGas(ctx, ethereum.CallMsg{
		From: payer, To: plan.To(), Value: plan.Value(), Data: data,
	})
	switch {
	case err != nil && d.Tamper != nil:
		// A tampered payload may be un-estimatable. The guard, not the RPC, is
		// what must refuse it, so use a fixed limit and let the guard decide.
		gasLimit = 100_000
		fmt.Fprintf(out, "note:      gas estimation failed (%v); using %d so the guard still runs\n", err, gasLimit)
	case err != nil:
		return Result{}, unavailable(fmt.Errorf("estimate gas: %w", err))
	case gasLimit > MaxGasLimit:
		return Result{}, violation(fmt.Errorf("%w: endpoint estimated %d gas for an ERC-20 transfer (bound %d)", ErrUnboundedGas, gasLimit, MaxGasLimit))
	default:
		gasLimit += gasLimit / 5 // 20% headroom; cannot overflow, gasLimit <= MaxGasLimit
	}
	plan.GasLimit = gasLimit
	fmt.Fprintf(out, "\ngas limit: %d\n", gasLimit)
	fmt.Fprintf(out, "fee cap:   %s per gas (base %s + tip %s)\n", feeCap, head.BaseFee, tip)
	fmt.Fprintf(out, "worst-case fee: %s of %s native units\n", new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), feeCap), maxGasCost)

	// ── 5. Bind the payment the enforcement point authorized ───────────────
	bound, err := NewBinding(cfg.Net, merchant, payer, amount, nonce, maxGasCost)
	if err != nil {
		return Result{}, violation(fmt.Errorf("binding: %w", err))
	}

	// ── 6. Build the signer FIRST ──────────────────────────────────────────
	//
	// go-ethereum hashes the SIGNER's chain id into the signing preimage and
	// overwrites the transaction's own ChainID with it, so the field the guard
	// asserts is not by itself the field that enters the signature. Pinning the
	// signer to the same constant before the guard runs means assertion 3 and
	// the preimage cannot drift.
	signer := NewSigner(cfg.Net)
	if sc := signer.ChainID(); !sc.IsUint64() || sc.Uint64() != bound.ChainID() {
		return Result{}, violation(fmt.Errorf("%w: signer %s, bound %d", ErrSignerMismatch, sc, bound.ChainID()))
	}

	// ── 7. Build, then read it BACK off the object ─────────────────────────
	tx, err := plan.Build()
	if err != nil {
		return Result{}, violation(err)
	}
	view, err := ViewOf(tx, evm.Address(payer))
	if err != nil {
		return Result{}, violation(err)
	}

	// ── 8. §A.4 pre-sign gate ──────────────────────────────────────────────
	verified, err := evm.Verify(view, bound)
	if err != nil {
		return Result{}, violation(fmt.Errorf("REFUSING TO SIGN: the settle guard rejected the transaction: %w\n"+
			"  Nothing was signed. Nothing was broadcast. No funds moved.", err))
	}
	fmt.Fprintf(out, "\nguard:     PASS: the transaction matches the authorized payment\n")
	if d.DryRun {
		fmt.Fprintln(out, "dry run:   stopping before the signature, as asked.")
		return Result{Payer: payer}, nil
	}

	// ── 9. Sign, then re-check ─────────────────────────────────────────────
	signKey := cfg.Key
	if d.DecoyKey != nil {
		signKey = d.DecoyKey
		fmt.Fprintf(out, "[tamper]   signing with an unauthorized key %s\n", crypto.PubkeyToAddress(d.DecoyKey.PublicKey))
	}
	if !now().Before(p.NotAfter) {
		return Result{}, violation(fmt.Errorf("%w; nothing was signed", ErrExpired))
	}
	signed, err := types.SignTx(tx, signer, signKey)
	if err != nil {
		return Result{}, unavailable(fmt.Errorf("sign: %w", err))
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return Result{}, violation(fmt.Errorf("cannot recover the sender from the signature: %w", err))
	}
	signedView, err := ViewOf(signed, evm.Address(sender))
	if err != nil {
		return Result{}, violation(err)
	}
	if err := verified.AssertSame(signedView); err != nil {
		return Result{}, violation(fmt.Errorf("REFUSING TO BROADCAST: the signed transaction is not the one that was verified: %w\n"+
			"  A signature exists in memory and is being discarded. Nothing was broadcast. No funds moved.", err))
	}
	fmt.Fprintf(out, "post-sign: PASS: recovered sender %s matches, every field unchanged\n", sender)

	// ── 10. Broadcast and confirm ──────────────────────────────────────────
	if err := cfg.Client.SendTransaction(ctx, signed); err != nil {
		return Result{}, unavailable(fmt.Errorf("broadcast: %w", err))
	}
	fmt.Fprintf(out, "\nsent:      %s%s\n", cfg.Net.ExplorerTxPrefix, signed.Hash().Hex())

	waitCtx, cancel := context.WithTimeout(parent, confirm)
	defer cancel()
	receipt, err := bind.WaitMined(waitCtx, cfg.Client, signed)
	if err != nil {
		return Result{TxHash: signed.Hash(), Payer: payer}, unavailable(fmt.Errorf("broadcast %s but NOT confirmed within %s: %w\n"+
			"  The transaction may still land. Check the explorer before retrying.", signed.Hash().Hex(), confirm, err))
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return Result{TxHash: signed.Hash(), Payer: payer}, unavailable(fmt.Errorf("transaction %s reverted on chain (status %d, gas used %d)", signed.Hash().Hex(), receipt.Status, receipt.GasUsed))
	}
	return Result{TxHash: signed.Hash(), Block: receipt.BlockNumber.Uint64(), GasUsed: receipt.GasUsed, Payer: payer}, nil
}

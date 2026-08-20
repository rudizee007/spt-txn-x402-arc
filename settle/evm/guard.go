package evm

import (
	"errors"
	"fmt"
	"math/big"
)

// boundAmountBits is the width of the amount field in the published intent
// binding (SPEC-X402 §4: u128, 16 bytes little-endian). A bound amount wider
// than this corresponds to no representable binding and is refused, never
// clamped — the same reason the Solana guard refuses a bound amount that does
// not fit the u64 an SPL transfer can carry.
const boundAmountBits = 128

// TxTypeDynamicFee is the EIP-1559 typed-transaction envelope byte. It is the
// ONLY transaction type this profile settles.
//
// This is the assertion that stops the guard from authorizing by omission. A
// transaction is an open structure: type 3 carries blob commitments, type 4
// (EIP-7702) carries an authorization list that installs code at the signer's
// own EOA. A guard that models `to`, `value` and `data` and says nothing about
// the type certifies "exactly the bound payment and nothing else" for a payload
// that also hands an attacker permanent control of the payer's account. Pin the
// type, and refuse every field the type does not have.
const TxTypeDynamicFee uint8 = 2

// Transaction is the EVM transaction that is about to be signed, or that has
// just been signed, with its fields already resolved.
//
// Every field an EIP-1559 transaction can carry appears here, including the
// ones that cannot move value (nonce, gas, access list). That is deliberate:
// a field the guard cannot see is a field the guard permits. The three list
// lengths are lengths rather than contents because the assertion on them is
// "empty", and a length is the smallest thing that can express it.
//
// Signer is the account whose key produces the signature. On EVM the sender is
// recovered from the signature rather than carried in the payload, so the
// pre-sign check asserts the intended signer and the caller re-checks the
// recovered sender afterwards via Verified.AssertSame.
type Transaction struct {
	Type    uint8
	ChainID uint64
	Nonce   uint64

	// GasLimit and MaxFeePerGas bound the worst-case fee. On Arc the fee is
	// paid in USDC — the same pool of funds as the payment — so an unbounded
	// fee is an unbounded second payment (SPEC-X402-ARC §A.3, §A.5.9).
	GasLimit     uint64
	MaxFeePerGas *big.Int

	To    *Address // nil means contract creation, which is never a bound payment
	Value *big.Int // native-asset value moved by the transaction itself
	Data  []byte   // calldata

	AccessListLen        int
	AuthorizationListLen int
	BlobHashLen          int

	Signer Address
}

// Binding is the authorized payment as it comes out of the gate: the 32-byte
// account identifiers the intent binding actually carries, plus the chain,
// amount, transaction nonce and fee ceiling.
//
// Identifiers are 32 bytes, not Address, on purpose. It forces every bound
// payment through the §A.2 narrowing — including its rejection of a dirty
// identifier — instead of letting a caller take the low 20 bytes by hand and
// never touch the codec. Fields are named so two same-typed identifiers cannot
// be transposed at a call site.
type Binding struct {
	ChainID uint64
	Asset   [AccountIDLen]byte
	PayTo   [AccountIDLen]byte
	Payer   [AccountIDLen]byte
	Amount  *big.Int // atomic units of the asset — micro-USDC here, never the native 18-decimal view
	Nonce   uint64   // the transaction nonce this authorization is spent on

	// MaxGasCost caps GasLimit × MaxFeePerGas, in the native 18-decimal view.
	// It is the compensating control for gas being outside the intent binding.
	MaxGasCost *big.Int
}

// BoundPayment is a validated Binding. Its fields are unexported and there is
// no literal form: the only way to obtain one is NewBoundPayment, so a bound
// payment that skipped validation cannot be constructed.
type BoundPayment struct {
	bound      bool
	chainID    uint64
	asset      Address
	payTo      Address
	payer      Address
	amount     *big.Int
	nonce      uint64
	maxGasCost *big.Int
}

var (
	// ErrMissingField reports a nil required *big.Int. A nil is never read as
	// "zero" or "any": an unset field means the caller does not know what will
	// be signed, which is a refusal, not a default.
	ErrMissingField = errors.New("settle/evm: transaction has a missing required field")

	// ErrUnsetAddress reports the zero address where an account is required.
	// Address is a value type, so an omitted field is 0x00…00 rather than nil;
	// without this, forgetting to set Payer and Signer makes the authority
	// assertion a 0x0 == 0x0 no-op.
	ErrUnsetAddress = errors.New("settle/evm: account address is unset (zero address)")

	// ErrNotBound reports a BoundPayment that did not come from NewBoundPayment.
	ErrNotBound = errors.New("settle/evm: bound payment was not constructed by NewBoundPayment")

	// ErrAmountRange reports a bound amount that is nil, negative, or wider
	// than the binding's u128.
	ErrAmountRange = errors.New("settle/evm: bound amount is nil, negative, or exceeds u128")

	// ErrGasCostRange reports a nil or negative fee ceiling.
	ErrGasCostRange = errors.New("settle/evm: bound gas-cost ceiling is nil or negative")

	// §A.4 assertions, one sentinel each so an operator can tell which control
	// fired — and so a DENY_VIOLATION record can say why (SPEC-X402 §5).
	ErrUnsupportedTxType        = errors.New("settle/evm: transaction type is not EIP-1559 (type 2)")         // 1
	ErrAccessListPresent        = errors.New("settle/evm: transaction carries an access list")                // 2
	ErrAuthorizationListPresent = errors.New("settle/evm: transaction carries an EIP-7702 authorization")     // 2
	ErrBlobHashesPresent        = errors.New("settle/evm: transaction carries blob hashes")                   // 2
	ErrChainIDMismatch          = errors.New("settle/evm: transaction chainId != bound chainId")              // 3
	ErrNonceMismatch            = errors.New("settle/evm: transaction nonce != bound nonce")                  // 4
	ErrContractCreation         = errors.New("settle/evm: transaction has no `to` (contract creation)")       // 5
	ErrAssetMismatch            = errors.New("settle/evm: transaction `to` != bound asset contract")          // 5
	ErrNonZeroValue             = errors.New("settle/evm: transaction moves native value (must be 0)")        // 6
	ErrGasCeilingExceeded       = errors.New("settle/evm: gasLimit × maxFeePerGas exceeds the bound ceiling") // 7
	ErrPayerMismatch            = errors.New("settle/evm: transaction signer != authorized payer")            // 8
	ErrDestinationMismatch      = errors.New("settle/evm: transfer recipient != bound payTo")                 // 11
	ErrAmountMismatch           = errors.New("settle/evm: transfer amount != bound amount")                   // 12

	// ErrNotVerified reports AssertSame called on a zero Verified.
	ErrNotVerified = errors.New("settle/evm: no verification was performed")

	// ErrPostSignDivergence reports that the signed transaction differs from
	// the one that was verified.
	ErrPostSignDivergence = errors.New("settle/evm: signed transaction differs from the verified transaction")
)

// NewBoundPayment validates a Binding and narrows its 32-byte identifiers to
// EVM addresses. Every rejection is a DENY_VIOLATION: an identifier with dirty
// high bytes, the zero address in any account position, an amount outside the
// binding's u128, or a missing fee ceiling.
func NewBoundPayment(b Binding) (BoundPayment, error) {
	var out BoundPayment

	asset, err := AddressFromAccountID(b.Asset)
	if err != nil {
		return out, fmt.Errorf("asset: %w", err)
	}
	payTo, err := AddressFromAccountID(b.PayTo)
	if err != nil {
		return out, fmt.Errorf("payTo: %w", err)
	}
	payer, err := AddressFromAccountID(b.Payer)
	if err != nil {
		return out, fmt.Errorf("payer: %w", err)
	}
	for name, a := range map[string]Address{"asset": asset, "payTo": payTo, "payer": payer} {
		if a.IsZero() {
			return out, fmt.Errorf("%s: %w", name, ErrUnsetAddress)
		}
	}
	if b.Amount == nil || b.Amount.Sign() < 0 || b.Amount.BitLen() > boundAmountBits {
		return out, ErrAmountRange
	}
	if b.MaxGasCost == nil || b.MaxGasCost.Sign() < 0 {
		return out, ErrGasCostRange
	}
	return BoundPayment{
		bound:      true,
		chainID:    b.ChainID,
		asset:      asset,
		payTo:      payTo,
		payer:      payer,
		amount:     new(big.Int).Set(b.Amount), // defensive copy: the caller cannot move the target after the check
		nonce:      b.Nonce,
		maxGasCost: new(big.Int).Set(b.MaxGasCost),
	}, nil
}

// Accessors for display and for building the transaction. Each returns a copy,
// so nothing a caller does to the result can change what was bound.
func (b BoundPayment) ChainID() uint64      { return b.chainID }
func (b BoundPayment) Asset() Address       { return b.asset }
func (b BoundPayment) PayTo() Address       { return b.payTo }
func (b BoundPayment) Payer() Address       { return b.payer }
func (b BoundPayment) Nonce() uint64        { return b.nonce }
func (b BoundPayment) Amount() *big.Int     { return new(big.Int).Set(b.amount) }
func (b BoundPayment) MaxGasCost() *big.Int { return new(big.Int).Set(b.maxGasCost) }

// Verified is proof that a specific transaction passed the §A.4 assertion. It
// holds a private deep copy of exactly what was checked, so a caller cannot
// mutate the checked bytes out from under the verdict, and the signing path can
// require a Verified rather than an error the caller may ignore.
//
// Its zero value is useless by construction: AssertSame on it fails closed.
type Verified struct {
	ok bool
	tx Transaction
	b  BoundPayment
}

// deepCopy detaches every pointer and slice a caller could still hold.
func deepCopy(t Transaction) Transaction {
	c := t
	c.Data = append([]byte(nil), t.Data...)
	if t.MaxFeePerGas != nil {
		c.MaxFeePerGas = new(big.Int).Set(t.MaxFeePerGas)
	}
	if t.Value != nil {
		c.Value = new(big.Int).Set(t.Value)
	}
	if t.To != nil {
		to := *t.To
		c.To = &to
	}
	return c
}

// Transaction returns a copy of the transaction that was verified.
func (v Verified) Transaction() Transaction { return deepCopy(v.tx) }

// BoundPayment returns the payment the transaction was verified against.
func (v Verified) BoundPayment() BoundPayment { return v.b }

// Verify is the SPEC-X402-ARC §A.4 pre-sign gate. Call it immediately before
// signing; a non-nil error means DO NOT SIGN (abort, DENY_VIOLATION).
//
// It copies the transaction first and asserts against the copy, so the Verified
// it returns describes exactly the bytes that were checked.
//
//  1. type      == 2 (EIP-1559)          — no blob or EIP-7702 payload
//  2. access, authorization and blob lists are empty
//  3. chainId   == bound chainId         — no cross-chain settlement
//  4. nonce     == bound nonce           — one authorization, one transaction
//  5. to        == bound asset contract  — no router, proxy or multicall
//  6. value     == 0                     — no native USDC alongside the payload
//  7. gasLimit × maxFeePerGas ≤ ceiling  — bounded fee, in the same asset
//  8. signer    == authorized payer, and is not the zero address
//  9. len(data) == 68 exactly            — no appended calldata tail
//  10. selector  == transfer(address,uint256), address word has clean high bytes
//  11. recipient == bound payTo
//  12. amount    == bound amount
//
// Assertion 6 is the one with no Solana analogue and the one that matters most
// on Arc. USDC there is the native gas asset AND this ERC-20 — one pool of
// funds, two interfaces, two scales. A transaction can carry a perfectly bound
// 1-USDC transfer in its calldata and drain an arbitrary balance through
// `value` at the same time. A calldata-only guard authorizes the first and
// signs away the second (§A.5.1).
func Verify(t Transaction, b BoundPayment) (Verified, error) {
	if !b.bound {
		return Verified{}, ErrNotBound
	}
	c := deepCopy(t)

	if c.MaxFeePerGas == nil || c.Value == nil {
		return Verified{}, ErrMissingField
	}
	// 1. envelope
	if c.Type != TxTypeDynamicFee {
		return Verified{}, ErrUnsupportedTxType
	}
	// 2. nothing the envelope should not carry
	if c.AccessListLen != 0 {
		return Verified{}, ErrAccessListPresent
	}
	if c.AuthorizationListLen != 0 {
		return Verified{}, ErrAuthorizationListPresent
	}
	if c.BlobHashLen != 0 {
		return Verified{}, ErrBlobHashesPresent
	}
	// 3. chain
	if c.ChainID != b.chainID {
		return Verified{}, ErrChainIDMismatch
	}
	// 4. one authorization, one transaction
	if c.Nonce != b.nonce {
		return Verified{}, ErrNonceMismatch
	}
	// 5. call target
	if c.To == nil {
		return Verified{}, ErrContractCreation
	}
	if !c.To.Equal(b.asset) {
		return Verified{}, ErrAssetMismatch
	}
	// 6. no native value alongside the payload
	if c.Value.Sign() != 0 {
		return Verified{}, ErrNonZeroValue
	}
	// 7. bounded fee
	if c.MaxFeePerGas.Sign() < 0 {
		return Verified{}, ErrGasCeilingExceeded
	}
	cost := new(big.Int).Mul(new(big.Int).SetUint64(c.GasLimit), c.MaxFeePerGas)
	if cost.Cmp(b.maxGasCost) > 0 {
		return Verified{}, ErrGasCeilingExceeded
	}
	// 8. authority
	if c.Signer.IsZero() {
		return Verified{}, ErrUnsetAddress
	}
	if !c.Signer.Equal(b.payer) {
		return Verified{}, ErrPayerMismatch
	}
	// 9. calldata length, asserted here as well as in DecodeTransfer so
	// loosening the decoder cannot silently loosen the guard.
	if len(c.Data) != TransferCalldataLen {
		return Verified{}, ErrCalldataLength
	}
	// 10. calldata structure
	dec, err := DecodeTransfer(c.Data)
	if err != nil {
		return Verified{}, err
	}
	// 11. recipient
	if !dec.To.Equal(b.payTo) {
		return Verified{}, ErrDestinationMismatch
	}
	// 12. amount
	if dec.Amount.Cmp(b.amount) != 0 {
		return Verified{}, ErrAmountMismatch
	}
	return Verified{ok: true, tx: c, b: b}, nil
}

// AssertSame re-checks a transaction against what was verified, field by field.
// Call it after signing, with Signer set to the sender RECOVERED from the
// signature and every other field read back from the signed transaction object.
// It closes the window between the assertion and the signature: a builder that
// rebuilds, a signer that picks a different key, a field mirrored wrongly into
// the guard's view — all of them show up here as a divergence.
func (v Verified) AssertSame(t Transaction) error {
	if !v.ok {
		return ErrNotVerified
	}
	if t.MaxFeePerGas == nil || t.Value == nil {
		return fmt.Errorf("%w: missing required field", ErrPostSignDivergence)
	}
	w := v.tx
	switch {
	case t.Type != w.Type:
		return fmt.Errorf("%w: type %d != %d", ErrPostSignDivergence, t.Type, w.Type)
	case t.ChainID != w.ChainID:
		return fmt.Errorf("%w: chainId %d != %d", ErrPostSignDivergence, t.ChainID, w.ChainID)
	case t.Nonce != w.Nonce:
		return fmt.Errorf("%w: nonce %d != %d", ErrPostSignDivergence, t.Nonce, w.Nonce)
	case t.GasLimit != w.GasLimit:
		return fmt.Errorf("%w: gasLimit %d != %d", ErrPostSignDivergence, t.GasLimit, w.GasLimit)
	case t.MaxFeePerGas.Cmp(w.MaxFeePerGas) != 0:
		return fmt.Errorf("%w: maxFeePerGas %s != %s", ErrPostSignDivergence, t.MaxFeePerGas, w.MaxFeePerGas)
	case t.To == nil || w.To == nil || !t.To.Equal(*w.To):
		return fmt.Errorf("%w: `to` changed", ErrPostSignDivergence)
	case t.Value.Cmp(w.Value) != 0:
		return fmt.Errorf("%w: value %s != %s", ErrPostSignDivergence, t.Value, w.Value)
	case string(t.Data) != string(w.Data):
		return fmt.Errorf("%w: calldata %x != %x", ErrPostSignDivergence, t.Data, w.Data)
	case t.AccessListLen != w.AccessListLen || t.AuthorizationListLen != w.AuthorizationListLen || t.BlobHashLen != w.BlobHashLen:
		return fmt.Errorf("%w: envelope lists changed", ErrPostSignDivergence)
	case !t.Signer.Equal(w.Signer):
		return fmt.Errorf("%w: sender %s != authorized payer %s", ErrPostSignDivergence, t.Signer.Hex(), w.Signer.Hex())
	}
	return nil
}

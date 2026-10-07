// Package eip3009 is the pre-sign guard for an x402 `exact` payment on EVM: an
// EIP-3009 TransferWithAuthorization that a facilitator submits later
// (SPEC-ARC-M3 §4.1).
//
// The guard constructs the authorization from the binding, computes its EIP-712
// digest itself, and accepts a signature only over that digest, by the bound
// payer (invariant M2). It never decodes a message someone else built in order
// to sign it. Where it is shown one (observe mode, or a provider's echo), it
// compares that message field by field with the one it constructed.
//
// Assertions (§4.1.2):
//
//  1. verifyingContract == the bound asset contract
//  2. chainId == the bound chain; name and version == the pinned values
//  3. primary type == TransferWithAuthorization (the only variant, O-2)
//  4. from == the authorized payer, not the zero address
//  5. to == the bound recipient
//  6. value == the bound amount
//  7. validAfter <= now; validBefore <= min(capability expiry, call expiry,
//     now + max lifetime); validBefore > validAfter (§4.1.3, O-3)
//  8. nonce == SHA-256("spt-txn-eip3009-nonce-v1" || 0x00 || intent digest) (§4.1.4, O-1)
//  9. after signing: the signature recovers to `from` over this digest, with a
//     low-s value and v in {27, 28}
//
// Signature recovery needs secp256k1, which this package does not carry. The
// caller recovers the signer (the build-tagged arc code does, with
// go-ethereum), and this package checks the result and the signature's form.
// Dependencies: the standard library and golang.org/x/crypto/sha3.
package eip3009

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// Type hashes, as published in Circle's FiatToken (contracts/v2/EIP3009.sol and
// contracts/util/EIP712.sol); a test recomputes each from its type string.
var (
	domainTypeHash   = keccak([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	transferTypeHash = keccak([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
)

// PrimaryType is the only EIP-3009 variant this guard signs (O-2).
const PrimaryType = "TransferWithAuthorization"

// Refusal classes.
var (
	ErrViolation = errors.New("eip3009: refused")
	ErrNotBound  = errors.New("eip3009: binding was not validated")
)

// Domain is a token's EIP-712 domain. Name and Version are pinned per contract
// and chain in configuration, never adopted from a payment requirement.
type Domain struct {
	Name              string
	Version           string
	ChainID           uint64
	VerifyingContract evm.Address
}

// Binding is what the gateway authorized, plus the clock and lifetime limits
// the window is derived from.
type Binding struct {
	Domain Domain
	From   evm.Address // the payer whose key signs
	To     evm.Address // the bound recipient
	Value  *big.Int    // atomic units of the asset
	Intent intent.Digest

	CapabilityExpiry time.Time
	CallExpiry       time.Time
	MaxLifetime      time.Duration
}

// Authorization is a TransferWithAuthorization message.
type Authorization struct {
	PrimaryType string
	Domain      Domain
	From        evm.Address
	To          evm.Address
	Value       *big.Int
	ValidAfter  *big.Int
	ValidBefore *big.Int
	Nonce       [32]byte
}

// Bound is a validated binding and the authorization constructed from it. It
// has no literal form: the only way to obtain one is Bind.
type Bound struct {
	ok     bool
	auth   Authorization
	digest [32]byte
	now    int64
}

// maxUint256 bounds every uint256 field.
var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// Bind validates b and constructs the one authorization the guard will sign,
// at time now.
//
// validAfter is 0: it is <= now, and the lifetime bound is carried by
// validBefore. validBefore is the earliest of the capability expiry, the call
// expiry and now + MaxLifetime, in whole seconds rounded down, and must be
// after now.
func Bind(b Binding, now time.Time) (Bound, error) {
	switch {
	case b.Domain.Name == "" || b.Domain.Version == "":
		return Bound{}, fmt.Errorf("%w: domain name and version must be pinned", ErrViolation)
	case b.Domain.ChainID == 0:
		return Bound{}, fmt.Errorf("%w: chain id is zero", ErrViolation)
	case b.Domain.VerifyingContract.IsZero():
		return Bound{}, fmt.Errorf("%w: asset contract is unset", ErrViolation)
	case b.From.IsZero():
		return Bound{}, fmt.Errorf("%w: payer is unset", ErrViolation)
	case b.To.IsZero():
		return Bound{}, fmt.Errorf("%w: recipient is unset", ErrViolation)
	case b.Value == nil || b.Value.Sign() <= 0 || b.Value.Cmp(maxUint256) > 0:
		return Bound{}, fmt.Errorf("%w: amount must be positive and fit uint256", ErrViolation)
	case b.Intent == (intent.Digest{}):
		return Bound{}, fmt.Errorf("%w: intent digest is unset", ErrViolation)
	case b.MaxLifetime <= 0:
		return Bound{}, fmt.Errorf("%w: max authorization lifetime must be positive", ErrViolation)
	case b.CapabilityExpiry.IsZero() || b.CallExpiry.IsZero():
		return Bound{}, fmt.Errorf("%w: capability and call expiry are required", ErrViolation)
	}
	end := b.CapabilityExpiry
	if b.CallExpiry.Before(end) {
		end = b.CallExpiry
	}
	if lim := now.Add(b.MaxLifetime); lim.Before(end) {
		end = lim
	}
	// Unix() rounds down for every instant after 1970; an earlier end is refused
	// just below as already expired.
	validBefore := end.Unix()
	if validBefore <= now.Unix() {
		return Bound{}, fmt.Errorf("%w: the authorization has already expired", ErrViolation)
	}
	a := Authorization{
		PrimaryType: PrimaryType,
		Domain:      b.Domain,
		From:        b.From,
		To:          b.To,
		Value:       new(big.Int).Set(b.Value),
		ValidAfter:  new(big.Int),
		ValidBefore: big.NewInt(validBefore),
		Nonce:       intent.EIP3009Nonce(b.Intent),
	}
	return Bound{ok: true, auth: a, digest: digest(a), now: now.Unix()}, nil
}

// Authorization returns a copy of the constructed message.
func (b Bound) Authorization() Authorization { return copyAuth(b.auth) }

// Digest returns the EIP-712 digest the payer signs.
func (b Bound) Digest() [32]byte { return b.digest }

// Verify checks a message someone else presents (observe mode, a provider's
// echo) against the constructed one, and states the first assertion it fails.
func (b Bound) Verify(a Authorization) error {
	if !b.ok {
		return ErrNotBound
	}
	w := b.auth
	switch {
	case a.Domain.VerifyingContract != w.Domain.VerifyingContract:
		return fmt.Errorf("%w (1): verifyingContract %s is not the bound asset %s", ErrViolation, a.Domain.VerifyingContract.Hex(), w.Domain.VerifyingContract.Hex())
	case a.Domain.ChainID != w.Domain.ChainID:
		return fmt.Errorf("%w (2): chainId %d is not the bound chain %d", ErrViolation, a.Domain.ChainID, w.Domain.ChainID)
	case a.Domain.Name != w.Domain.Name || a.Domain.Version != w.Domain.Version:
		return fmt.Errorf("%w (2): domain name/version is not the pinned value", ErrViolation)
	case a.PrimaryType != PrimaryType:
		return fmt.Errorf("%w (3): primary type %q is not %s", ErrViolation, a.PrimaryType, PrimaryType)
	case a.From.IsZero() || a.From != w.From:
		return fmt.Errorf("%w (4): from %s is not the authorized payer", ErrViolation, a.From.Hex())
	case a.To != w.To:
		return fmt.Errorf("%w (5): to %s is not the bound recipient", ErrViolation, a.To.Hex())
	case a.Value == nil || a.Value.Cmp(w.Value) != 0:
		return fmt.Errorf("%w (6): value is not the bound amount", ErrViolation)
	case a.ValidAfter == nil || a.ValidAfter.Sign() < 0 || a.ValidAfter.Cmp(big.NewInt(b.now)) > 0:
		return fmt.Errorf("%w (7): validAfter is in the future or malformed", ErrViolation)
	case a.ValidBefore == nil || a.ValidBefore.Cmp(w.ValidBefore) > 0:
		return fmt.Errorf("%w (7): validBefore outlives the authorization (limit %s)", ErrViolation, w.ValidBefore)
	case a.ValidBefore.Cmp(a.ValidAfter) <= 0 || a.ValidBefore.Cmp(big.NewInt(b.now)) <= 0:
		return fmt.Errorf("%w (7): the window is empty or already closed", ErrViolation)
	case a.Nonce != w.Nonce:
		return fmt.Errorf("%w (8): nonce is not the one derived from the intent digest", ErrViolation)
	}
	return nil
}

// secp256k1 group order n and n/2, for the low-s rule.
var (
	secpN, _     = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secpHalfN    = new(big.Int).Rsh(secpN, 1)
	errSignature = fmt.Errorf("%w (9): signature", ErrViolation)
)

// CheckSigned is assertion 9. sig is the 65-byte r || s || v signature the
// signer returned; recovered is the address the caller recovered from sig over
// b.Digest(). It refuses a malformed or high-s signature, a v other than 27/28
// (or 0/1), and a recovered address other than the bound payer.
func (b Bound) CheckSigned(sig []byte, recovered evm.Address) error {
	if !b.ok {
		return ErrNotBound
	}
	if len(sig) != 65 {
		return fmt.Errorf("%w: length %d, want 65", errSignature, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Sign() == 0 || s.Cmp(secpN) >= 0 {
		return fmt.Errorf("%w: r or s out of range", errSignature)
	}
	if s.Cmp(secpHalfN) > 0 {
		return fmt.Errorf("%w: high-s (malleable) value", errSignature)
	}
	if v := sig[64]; v != 27 && v != 28 && v != 0 && v != 1 {
		return fmt.Errorf("%w: v=%d", errSignature, v)
	}
	if recovered.IsZero() || recovered != b.auth.From {
		return fmt.Errorf("%w: recovers to %s, not the authorized payer %s", errSignature, recovered.Hex(), b.auth.From.Hex())
	}
	return nil
}

// digest computes the EIP-712 digest of a constructed authorization:
// keccak256(0x19 0x01 || domainSeparator || hashStruct(message)). Only values
// Bind has bounded reach it.
func digest(a Authorization) [32]byte {
	name, version := keccak([]byte(a.Domain.Name)), keccak([]byte(a.Domain.Version))
	dom := keccak(domainTypeHash[:], name[:], version[:],
		word(new(big.Int).SetUint64(a.Domain.ChainID)), addressWord(a.Domain.VerifyingContract))
	msg := keccak(transferTypeHash[:], addressWord(a.From), addressWord(a.To),
		word(a.Value), word(a.ValidAfter), word(a.ValidBefore), a.Nonce[:])
	return keccak([]byte{0x19, 0x01}, dom[:], msg[:])
}

func keccak(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func word(v *big.Int) []byte {
	out := make([]byte, 32)
	if v != nil {
		v.FillBytes(out) // panics above 2^256; every caller has bounded v
	}
	return out
}

func addressWord(a evm.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], a[:])
	return out
}

func copyAuth(a Authorization) Authorization {
	c := a
	for _, p := range []**big.Int{&c.Value, &c.ValidAfter, &c.ValidBefore} {
		if *p != nil {
			*p = new(big.Int).Set(*p)
		}
	}
	return c
}

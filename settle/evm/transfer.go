package evm

import (
	"crypto/subtle"
	"errors"
	"math/big"
)

// TransferSelector is the ERC-20 `transfer(address,uint256)` function selector —
// the first four bytes of Keccak-256("transfer(address,uint256)").
//
// It is a hardcoded constant because this package computes no Keccak (that
// would mean a third-party dependency in the guard, or hand-rolling a
// primitive, and the second is an automatic reject). A hardcoded constant that
// nothing checks is not acceptable either, so the settlement command — which
// already links an audited Keccak — recomputes it at start-up and refuses to
// run on disagreement (SPEC-X402-ARC §A.3, §A.7).
// It is an unexported var with an exported accessor: an exported package-level
// var could be reassigned by any init() in any package linked into the same
// binary, after which DecodeTransfer would accept approve(attacker, 2^256-1) as
// a bound transfer — a standing allowance, which is §A.5.6's exact prohibition.
var transferSelector = [4]byte{0xa9, 0x05, 0x9c, 0xbb}

// TransferSelector returns the ERC-20 transfer selector by value.
func TransferSelector() [4]byte { return transferSelector }

// Calldata layout of a bound transfer, all offsets derived, none magic.
const (
	selectorLen = 4
	wordLen     = 32

	// TransferCalldataLen is the EXACT length of the calldata of a bound
	// transfer: selector + address word + amount word. Not a minimum. The
	// Solidity ABI decoder ignores trailing calldata, so `>=` would admit an
	// appended tail that a fallback or a non-standard token may act on
	// (SPEC-X402-ARC §A.5.4).
	TransferCalldataLen = selectorLen + 2*wordLen // 68

	addrWordOff = selectorLen                        // 4
	addrOff     = addrWordOff + wordLen - AddressLen // 16
	amountOff   = selectorLen + wordLen              // 36
)

var (
	// ErrCalldataLength reports calldata whose length is not exactly
	// TransferCalldataLen — too short to decode, or carrying a tail.
	ErrCalldataLength = errors.New("evm: calldata is not exactly 68 bytes")

	// ErrNotTransfer reports a selector other than transfer(address,uint256).
	// approve, transferFrom, permit and every batching entry point land here
	// (SPEC-X402-ARC §A.5.3, §A.5.6).
	ErrNotTransfer = errors.New("evm: calldata is not transfer(address,uint256)")

	// ErrDirtyAddressWord reports non-zero bytes in the high 12 bytes of the
	// address argument. The ABI decoder ignores them, so calldata carrying them
	// decodes to the reviewed recipient while differing from the reviewed bytes
	// (SPEC-X402-ARC §A.5.5).
	ErrDirtyAddressWord = errors.New("evm: transfer address argument has dirty high bytes")

	// ErrEncodeAmountRange reports an amount that cannot be encoded into a
	// uint256 word. Distinct from ErrAmountRange, which is about the binding's
	// narrower u128: an operator reading a decision record must be able to tell
	// which rule fired.
	ErrEncodeAmountRange = errors.New("evm: transfer amount is nil, negative, or exceeds uint256")
)

// DecodedTransfer is the meaningful content of an ERC-20 transfer call: who
// receives how much. There is no sender field — on EVM the sender is the
// transaction signer, which is a transaction-level property and is asserted
// separately (§A.4 assertion 9).
type DecodedTransfer struct {
	To     Address
	Amount *big.Int // uint256, big-endian, as it appears in the calldata
}

// DecodeTransfer parses ERC-20 transfer(address,uint256) calldata. Any
// structural problem is an error — fail closed. Calldata that cannot be fully
// and exactly decoded is never asserted as matching.
//
// It never panics on arbitrary input: length is checked before every slice.
func DecodeTransfer(data []byte) (DecodedTransfer, error) {
	var t DecodedTransfer
	if len(data) != TransferCalldataLen {
		return t, ErrCalldataLength
	}
	if subtle.ConstantTimeCompare(data[:selectorLen], transferSelector[:]) != 1 {
		return t, ErrNotTransfer
	}
	var zero [wordLen - AddressLen]byte
	if subtle.ConstantTimeCompare(data[addrWordOff:addrOff], zero[:]) != 1 {
		return t, ErrDirtyAddressWord
	}
	copy(t.To[:], data[addrOff:amountOff])
	t.Amount = new(big.Int).SetBytes(data[amountOff:])
	return t, nil
}

// EncodeTransfer builds the calldata for transfer(to, amount). It is the
// builder side of the same layout the guard decodes — one layout, one file,
// differentially exercised by the round-trip tests, so the builder and the
// verifier cannot drift apart (threat model risk #1 applied to calldata).
//
// The amount must be non-negative and fit in a uint256 word; anything else is
// refused rather than silently wrapped.
func EncodeTransfer(to Address, amount *big.Int) ([]byte, error) {
	if amount == nil || amount.Sign() < 0 || amount.BitLen() > 8*wordLen {
		return nil, ErrEncodeAmountRange
	}
	data := make([]byte, TransferCalldataLen)
	copy(data[:selectorLen], transferSelector[:])
	copy(data[addrOff:amountOff], to[:])
	amount.FillBytes(data[amountOff:])
	return data, nil
}

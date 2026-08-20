// Package evm contains the payer-side settlement guard for the SPT-Txn x402
// flow on EVM chains — the Arc profile (docs/SPEC-X402-ARC.md). Its job is the
// §A.4 assertion: after the gate says ALLOW, and before anything is signed,
// prove the transaction that is about to be signed moves exactly the bound
// amount of the bound asset to the bound recipient under the bound payer's
// authority, and nothing else.
//
// Like the Solana `settle` package it deliberately imports no chain SDK: it
// operates on already-resolved transaction fields (chain id, to, value,
// calldata, intended signer), so it is dependency-free, offline-testable, and
// part of the default build. The transaction builder and signer that produce
// those fields plug in at settlement time (cmd/payarc, behind `-tags arc`).
//
// This file is the address codec. An EVM address is 20 bytes; the published
// intent binding (SPEC-X402 §4) carries 32-byte account identifiers. §A.2 fixes
// the widening as a left-pad with exactly 12 zero bytes, and requires the
// narrowing to reject any non-zero byte above the address rather than truncate.
package evm

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

// AddressLen is the width of an EVM account address in bytes.
const AddressLen = 20

// AccountIDLen is the width of an account identifier in the intent binding.
const AccountIDLen = 32

// padLen is the number of zero bytes prepended to widen an address to an
// account identifier. It is a derived constant, never a magic 12.
const padLen = AccountIDLen - AddressLen

// Address is a 20-byte EVM account address. It is the bytes, not the string:
// nothing in this package binds or compares the textual form.
type Address [AddressLen]byte

var (
	// ErrBadAddress reports a string that is not 0x followed by exactly 40 hex
	// digits. Length and alphabet are both hard errors — never a best-effort
	// parse, never a truncation.
	ErrBadAddress = errors.New("evm: address is not 0x followed by 40 hex digits")

	// ErrDirtyAccountID reports an account identifier whose bytes above the
	// 20-byte address are not all zero. Those bytes are ignored by the EVM ABI
	// but they are inside the binding preimage, so accepting them would let two
	// different bound identifiers mean the same on-chain account (SPEC-X402-ARC
	// §A.2, §A.5.5).
	ErrDirtyAccountID = errors.New("evm: account id has non-zero bytes above the 20-byte address")
)

// ParseAddress decodes "0x" + 40 hex digits into an Address. Input is
// case-insensitive and is lower-cased before decoding.
//
// EIP-55 checksums are NOT validated here, and mixed-case input is not treated
// as checksummed. EIP-55 requires Keccak-256, which is not in the Go standard
// library, and this package takes no third-party dependency; more importantly,
// what the guard binds is bytes, so a checksum would be a typo control rather
// than a security control (SPEC-X402-ARC §A.2). Stating that is better than
// implying a validation that does not happen.
func ParseAddress(s string) (Address, error) {
	var a Address
	if len(s) != 2+2*AddressLen {
		return a, ErrBadAddress
	}
	if s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return a, ErrBadAddress
	}
	raw, err := hex.DecodeString(strings.ToLower(s[2:]))
	if err != nil || len(raw) != AddressLen {
		return a, ErrBadAddress
	}
	copy(a[:], raw)
	return a, nil
}

// MustParseAddress is ParseAddress for compile-time constants in this package.
// A bad constant is a programming error, not a runtime condition — the same
// discipline as settle.mustHex32.
func MustParseAddress(s string) Address {
	a, err := ParseAddress(s)
	if err != nil {
		panic("evm: bad address constant: " + s)
	}
	return a
}

// Hex renders the address as lowercase "0x…". It is display only: no decision
// in this package is ever taken on a rendered string.
func (a Address) Hex() string { return "0x" + hex.EncodeToString(a[:]) }

// Equal reports whether two addresses are identical.
//
// The comparison is constant-time. Addresses are public values, so this is
// uniformity rather than a required control — but every comparison in the trust
// boundary going through one constant-time helper is what stops a later
// secret-adjacent comparison from being written with `==` because that is what
// the neighbouring line does.
func (a Address) Equal(b Address) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// IsZero reports whether the address is 0x00…00.
//
// Address is a value type, so an omitted struct field is the zero address
// rather than nil. Every account position in the trust boundary rejects it: the
// zero address is never a legitimate ERC-20 contract, recipient or signer, so
// treating "unset" as a hard error costs nothing and removes a whole class of
// vacuously-satisfied comparison.
func (a Address) IsZero() bool {
	var zero Address
	return subtle.ConstantTimeCompare(a[:], zero[:]) == 1
}

// AccountID32 widens the address into the 32-byte account identifier the intent
// binding carries: 12 zero bytes followed by the address (SPEC-X402-ARC §A.2).
func (a Address) AccountID32() [AccountIDLen]byte {
	var id [AccountIDLen]byte
	copy(id[padLen:], a[:])
	return id
}

// AddressFromAccountID narrows a 32-byte account identifier back to an Address,
// rejecting any identifier whose high bytes are not all zero. Round-trips with
// AccountID32 for every Address.
func AddressFromAccountID(id [AccountIDLen]byte) (Address, error) {
	var a Address
	var zero [padLen]byte
	if subtle.ConstantTimeCompare(id[:padLen], zero[:]) != 1 {
		return a, ErrDirtyAccountID
	}
	copy(a[:], id[padLen:])
	return a, nil
}

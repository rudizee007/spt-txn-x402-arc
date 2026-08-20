package evm

import (
	"crypto/subtle"
	"errors"

	"github.com/rudizee007/spt-txn-pep/gate"
)

// ErrTransportMismatch reports that a transport identifier the gate bound does
// not correspond to the address the settler is about to pay.
var ErrTransportMismatch = errors.New("settle/evm: bound transport identifier != address being settled")

// AccountIDBase58 renders an EVM address in the transport form the published
// x402 PaymentRequirements carries: base58 of the 32-byte account identifier
// (SPEC-X402-ARC §A.2). The gate's canonicalizer decodes exactly 32 bytes from
// base58, so the address is widened first.
//
// This is a transport encoding, not a display form. Show operators and video
// viewers Address.Hex(); show the gate this.
func AccountIDBase58(a Address) string {
	id := a.AccountID32()
	return gate.EncodeBase58(id[:])
}

// AssertTransportMatches proves that the identifier string the gate bound is
// the one that denotes this address.
//
// It re-encodes rather than decoding, on purpose. The PEP exports the encoder
// and keeps the decoder unexported; writing a second base58 decoder here would
// put two implementations of one encoding on the two sides of the same check,
// which is the canonicalization-mismatch shape this project treats as its
// number-one bug class. One direction, one implementation, no drift.
func AssertTransportMatches(a Address, transport string) error {
	want := AccountIDBase58(a)
	if subtle.ConstantTimeCompare([]byte(want), []byte(transport)) != 1 {
		return ErrTransportMismatch
	}
	return nil
}

//go:build arc

// Package eip3009sign signs and recovers EIP-3009 authorizations with
// go-ethereum's secp256k1, for the guard in settle/eip3009, which carries no
// curve code of its own. Every signature produced here is checked by the guard
// before it is returned (SPEC-ARC-M3 §4.1.2 assertion 9, invariant M3).
package eip3009sign

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// Recover returns the address that produced sig (r || s || v, v in 27/28 or
// 0/1) over digest.
func Recover(digest [32]byte, sig []byte) (evm.Address, error) {
	if len(sig) != 65 {
		return evm.Address{}, errors.New("eip3009sign: signature must be 65 bytes")
	}
	s := append([]byte(nil), sig...)
	if s[64] >= 27 {
		s[64] -= 27
	}
	pub, err := crypto.SigToPub(digest[:], s)
	if err != nil {
		return evm.Address{}, fmt.Errorf("eip3009sign: recover: %w", err)
	}
	return evm.Address(crypto.PubkeyToAddress(*pub)), nil
}

// Sign signs the guard's constructed authorization with key, then recovers and
// checks the result. It returns the 65-byte signature with v in {27, 28}.
func Sign(b eip3009.Bound, key *ecdsa.PrivateKey) ([]byte, error) {
	d := b.Digest()
	sig, err := crypto.Sign(d[:], key)
	if err != nil {
		return nil, fmt.Errorf("eip3009sign: sign: %w", err)
	}
	sig[64] += 27
	return sig, Check(b, sig)
}

// Check is assertion 9 for a signature from any signer (a local key, or a
// wallet provider's typed-data endpoint): recover it over the guard's digest and
// let the guard judge the result.
func Check(b eip3009.Bound, sig []byte) error {
	who, err := Recover(b.Digest(), sig)
	if err != nil {
		return fmt.Errorf("%w (9): %v", eip3009.ErrViolation, err)
	}
	return b.CheckSigned(sig, who)
}

//go:build arc

package arcpay

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// RemoteSigner signs a transaction held elsewhere, such as a Circle
// developer-controlled wallet (SPEC-ARC-M3 §4.2). It must sign without
// broadcasting. Nothing it returns is trusted: Settle decodes the signed
// transaction, recovers the sender, re-runs the guard's comparison on every
// field, checks the reported hash, and broadcasts the checked bytes itself.
type RemoteSigner interface {
	// Address is the account the signer signs for, the payer the guard binds.
	Address() common.Address
	// SignTransaction signs unsigned, an EIP-1559 transaction in its unsigned
	// serialization (UnsignedBytes). It returns the signed transaction's
	// EIP-2718 encoding and the transaction hash the provider reports.
	SignTransaction(ctx context.Context, unsigned []byte) (signed []byte, reportedHash common.Hash, err error)
}

// Errors specific to a remote signature.
var (
	ErrRemoteHash    = errors.New("arcpay: the signer's reported hash is not the hash of the transaction it returned")
	ErrRemoteEncoded = errors.New("arcpay: the signer returned a transaction that does not decode as one EIP-1559 transaction")
)

// UnsignedBytes is the unsigned serialization of a dynamic-fee transaction:
// 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to,
// value, data, accessList]). Its Keccak-256 is the EIP-1559 signing hash, which
// a test checks against go-ethereum's signer.
func UnsignedBytes(tx *types.Transaction) ([]byte, error) {
	if tx.Type() != types.DynamicFeeTxType || tx.To() == nil {
		return nil, fmt.Errorf("arcpay: only a dynamic-fee call transaction is signed remotely")
	}
	body, err := rlp.EncodeToBytes([]interface{}{
		tx.ChainId(), tx.Nonce(), tx.GasTipCap(), tx.GasFeeCap(), tx.Gas(),
		tx.To(), tx.Value(), tx.Data(), tx.AccessList(),
	})
	if err != nil {
		return nil, err
	}
	return append([]byte{types.DynamicFeeTxType}, body...), nil
}

// remoteSign asks the remote signer for a signature and decodes the result.
// It refuses an undecodable answer, a non-dynamic-fee type, and a reported hash
// that does not match what was returned. The caller re-checks every field.
func remoteSign(ctx context.Context, r RemoteSigner, tx *types.Transaction) (*types.Transaction, error) {
	unsigned, err := UnsignedBytes(tx)
	if err != nil {
		return nil, violation(err)
	}
	raw, reported, err := r.SignTransaction(ctx, unsigned)
	if err != nil {
		return nil, unavailable(fmt.Errorf("remote signer: %w", err))
	}
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(raw); err != nil || signed.Type() != types.DynamicFeeTxType {
		return nil, violation(fmt.Errorf("%w (%v)", ErrRemoteEncoded, err))
	}
	if signed.Hash() != reported {
		return nil, violation(fmt.Errorf("%w: reported %s, returned %s", ErrRemoteHash, reported.Hex(), signed.Hash().Hex()))
	}
	return signed, nil
}

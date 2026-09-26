package evm

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
)

// Log checkpoints on Arc (docs/SPEC-ARC-GATE.md §5).
//
// A checkpoint is a type-2 transaction from the checkpoint key's address to the
// same address, value 0, whose calldata is exactly CheckpointData(n, root): the
// head of the transparency log. It publishes evidence; it must never be able to
// move USDC. VerifyCheckpoint is the guard for that shape. It shares no code
// path with the payment guard's binding (Verify), so neither can be loosened
// through the other.

// CheckpointTag is the domain-separation prefix of checkpoint calldata.
const CheckpointTag = "spt-txn/translog-checkpoint/v1"

// CheckpointDataLen is len(CheckpointTag) + 8-byte count + 32-byte root.
const CheckpointDataLen = len(CheckpointTag) + 8 + 32

// CheckpointData encodes a log head: tag || n (uint64, big-endian) || root.
func CheckpointData(n uint64, root [32]byte) []byte {
	out := make([]byte, 0, CheckpointDataLen)
	out = append(out, CheckpointTag...)
	out = binary.BigEndian.AppendUint64(out, n)
	return append(out, root[:]...)
}

// CheckpointBinding is what one checkpoint transaction must be.
type CheckpointBinding struct {
	ChainID    uint64
	From       Address // the checkpoint key's address; also the only allowed `to`
	Nonce      uint64
	N          uint64
	Root       [32]byte
	MaxGasCost *big.Int // ceiling on gasLimit * maxFeePerGas, native units
}

var (
	ErrCheckpointBinding = errors.New("settle/evm: checkpoint binding is incomplete")
	ErrCheckpointShape   = errors.New("settle/evm: transaction is not a checkpoint")
	ErrCheckpointData    = errors.New("settle/evm: checkpoint calldata differs from the expected log head")
	ErrCheckpointGas     = errors.New("settle/evm: checkpoint fee exceeds its ceiling")
)

// VerifyCheckpoint returns nil only for exactly the checkpoint the binding
// describes. Run it on the transaction about to be signed, and again on the
// signed transaction with its recovered sender.
func VerifyCheckpoint(t Transaction, b CheckpointBinding) error {
	if b.ChainID == 0 || b.From.IsZero() || b.MaxGasCost == nil || b.MaxGasCost.Sign() <= 0 {
		return ErrCheckpointBinding
	}
	switch {
	case t.Type != TxTypeDynamicFee:
		return ErrCheckpointShape
	case t.AccessListLen != 0 || t.AuthorizationListLen != 0 || t.BlobHashLen != 0:
		return ErrCheckpointShape
	case t.ChainID != b.ChainID || t.Nonce != b.Nonce:
		return ErrCheckpointShape
	case t.To == nil || !t.To.Equal(b.From) || !t.Signer.Equal(b.From):
		return ErrCheckpointShape
	case t.Value == nil || t.Value.Sign() != 0:
		return ErrCheckpointShape
	}
	want := CheckpointData(b.N, b.Root)
	if len(t.Data) != len(want) || subtle.ConstantTimeCompare(t.Data, want) != 1 {
		return ErrCheckpointData
	}
	if t.MaxFeePerGas == nil || t.MaxFeePerGas.Sign() < 0 {
		return ErrCheckpointGas
	}
	cost := new(big.Int).Mul(new(big.Int).SetUint64(t.GasLimit), t.MaxFeePerGas)
	if cost.Cmp(b.MaxGasCost) > 0 {
		return ErrCheckpointGas
	}
	return nil
}

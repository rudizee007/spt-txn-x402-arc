package evm

import (
	"errors"
	"math/big"
	"testing"
)

var (
	cpFrom = MustParseAddress("0x4444444444444444444444444444444444444444")
	cpRoot = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
)

func cpPair() (Transaction, CheckpointBinding) {
	to := cpFrom
	return Transaction{
		Type: TxTypeDynamicFee, ChainID: ArcMainnetChainID, Nonce: 3,
		GasLimit: 30_000, MaxFeePerGas: big.NewInt(40_000_000_000),
		To: &to, Value: big.NewInt(0), Data: CheckpointData(12, cpRoot), Signer: cpFrom,
	}, CheckpointBinding{
		ChainID: ArcMainnetChainID, From: cpFrom, Nonce: 3, N: 12, Root: cpRoot,
		MaxGasCost: new(big.Int).Mul(big.NewInt(30_000), big.NewInt(40_000_000_000)),
	}
}

func TestCheckpointData_Layout(t *testing.T) {
	if len(CheckpointTag) != 30 || CheckpointDataLen != 70 {
		t.Fatalf("tag %d bytes, data %d bytes; the spec fixes 30 and 70", len(CheckpointTag), CheckpointDataLen)
	}
	d := CheckpointData(0x0102030405060708, cpRoot)
	if len(d) != 70 || string(d[:30]) != CheckpointTag || d[30] != 1 || d[37] != 8 || d[38] != 1 || d[69] != 32 {
		t.Fatalf("unexpected layout % x", d)
	}
}

func TestVerifyCheckpoint_AllowsExactlyTheCheckpoint(t *testing.T) {
	tx, b := cpPair()
	if err := VerifyCheckpoint(tx, b); err != nil {
		t.Fatalf("the exact checkpoint was refused: %v", err)
	}
}

func TestVerifyCheckpoint_Refusals(t *testing.T) {
	other := MustParseAddress("0x5555555555555555555555555555555555555555")
	usdcTransfer, _ := EncodeTransfer(other, big.NewInt(1_000_000))
	cases := []struct {
		name string
		mut  func(*Transaction, *CheckpointBinding)
		want error
	}{
		{"nonzero value", func(t *Transaction, _ *CheckpointBinding) { t.Value = big.NewInt(1) }, ErrCheckpointShape},
		{"nil value", func(t *Transaction, _ *CheckpointBinding) { t.Value = nil }, ErrCheckpointShape},
		{"to another address", func(t *Transaction, _ *CheckpointBinding) { t.To = &other }, ErrCheckpointShape},
		{"to the USDC contract", func(t *Transaction, _ *CheckpointBinding) { u := USDCArcMainnet; t.To = &u }, ErrCheckpointShape},
		{"contract creation", func(t *Transaction, _ *CheckpointBinding) { t.To = nil }, ErrCheckpointShape},
		{"signed by another key", func(t *Transaction, _ *CheckpointBinding) { t.Signer = other }, ErrCheckpointShape},
		{"wrong chain", func(t *Transaction, _ *CheckpointBinding) { t.ChainID = ArcTestnetChainID }, ErrCheckpointShape},
		{"wrong nonce", func(t *Transaction, _ *CheckpointBinding) { t.Nonce++ }, ErrCheckpointShape},
		{"legacy envelope", func(t *Transaction, _ *CheckpointBinding) { t.Type = 0 }, ErrCheckpointShape},
		{"access list", func(t *Transaction, _ *CheckpointBinding) { t.AccessListLen = 1 }, ErrCheckpointShape},
		{"authorization list", func(t *Transaction, _ *CheckpointBinding) { t.AuthorizationListLen = 1 }, ErrCheckpointShape},
		{"blob hashes", func(t *Transaction, _ *CheckpointBinding) { t.BlobHashLen = 1 }, ErrCheckpointShape},
		{"USDC transfer calldata", func(t *Transaction, _ *CheckpointBinding) { t.Data = usdcTransfer }, ErrCheckpointData},
		{"data off by one byte", func(t *Transaction, _ *CheckpointBinding) { t.Data[69] ^= 1 }, ErrCheckpointData},
		{"data one byte longer", func(t *Transaction, _ *CheckpointBinding) { t.Data = append(t.Data, 0) }, ErrCheckpointData},
		{"a different head", func(_ *Transaction, b *CheckpointBinding) { b.N++ }, ErrCheckpointData},
		{"fee over ceiling", func(t *Transaction, _ *CheckpointBinding) { t.GasLimit++ }, ErrCheckpointGas},
		{"nil fee", func(t *Transaction, _ *CheckpointBinding) { t.MaxFeePerGas = nil }, ErrCheckpointGas},
		{"negative fee", func(t *Transaction, _ *CheckpointBinding) { t.MaxFeePerGas = big.NewInt(-1) }, ErrCheckpointGas},
		{"binding without chain", func(_ *Transaction, b *CheckpointBinding) { b.ChainID = 0 }, ErrCheckpointBinding},
		{"binding without sender", func(_ *Transaction, b *CheckpointBinding) { b.From = Address{} }, ErrCheckpointBinding},
		{"binding without ceiling", func(_ *Transaction, b *CheckpointBinding) { b.MaxGasCost = nil }, ErrCheckpointBinding},
		{"binding with zero ceiling", func(_ *Transaction, b *CheckpointBinding) { b.MaxGasCost = big.NewInt(0) }, ErrCheckpointBinding},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, b := cpPair()
			c.mut(&tx, &b)
			if err := VerifyCheckpoint(tx, b); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// A payment the payment guard would accept is not a checkpoint, and a
// checkpoint is not a payment: the two guards do not accept each other's shape.
func TestVerifyCheckpoint_AndPaymentGuardRefuseEachOther(t *testing.T) {
	pay, bound := validPair(t)
	if err := VerifyCheckpoint(pay, CheckpointBinding{ChainID: pay.ChainID, From: pay.Signer, Nonce: pay.Nonce, N: 1, Root: cpRoot, MaxGasCost: big.NewInt(1 << 62)}); err == nil {
		t.Fatal("the checkpoint guard accepted a USDC payment")
	}
	cp, _ := cpPair()
	if _, err := Verify(cp, bound); err == nil {
		t.Fatal("the payment guard accepted a checkpoint")
	}
}

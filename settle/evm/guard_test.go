package evm

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"
)

var (
	boundAsset = USDCArcTestnet
	boundPayTo = MustParseAddress("0x2222222222222222222222222222222222222222")
	boundPayer = MustParseAddress("0x3333333333333333333333333333333333333333")
	attacker   = MustParseAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
)

const (
	boundMicroUSDC = 1_000_000 // 1.00 USDC
	boundNonce     = 7
	testGasLimit   = 60_000
)

// testMaxFeePerGas and testMaxGasCost leave exactly one unit of headroom, so a
// ceiling test can move by one.
var (
	testMaxFeePerGas = big.NewInt(2_000_000_000) // 2 gwei-equivalent, native 18-dec view
	testMaxGasCost   = new(big.Int).Mul(big.NewInt(testGasLimit), testMaxFeePerGas)
)

func mustBound(t testing.TB) BoundPayment {
	t.Helper()
	b, err := NewBoundPayment(Binding{
		ChainID:    ArcTestnetChainID,
		Asset:      boundAsset.AccountID32(),
		PayTo:      boundPayTo.AccountID32(),
		Payer:      boundPayer.AccountID32(),
		Amount:     big.NewInt(boundMicroUSDC),
		Nonce:      boundNonce,
		MaxGasCost: new(big.Int).Set(testMaxGasCost),
	})
	if err != nil {
		t.Fatalf("NewBoundPayment: %v", err)
	}
	return b
}

func validPair(t testing.TB) (Transaction, BoundPayment) {
	t.Helper()
	data, err := EncodeTransfer(boundPayTo, big.NewInt(boundMicroUSDC))
	if err != nil {
		t.Fatalf("EncodeTransfer: %v", err)
	}
	to := boundAsset
	return Transaction{
		Type:         TxTypeDynamicFee,
		ChainID:      ArcTestnetChainID,
		Nonce:        boundNonce,
		GasLimit:     testGasLimit,
		MaxFeePerGas: new(big.Int).Set(testMaxFeePerGas),
		To:           &to,
		Value:        big.NewInt(0),
		Data:         data,
		Signer:       boundPayer,
	}, mustBound(t)
}

func TestVerify_AllowsTheBoundTransfer(t *testing.T) {
	tx, b := validPair(t)
	v, err := Verify(tx, b)
	if err != nil {
		t.Fatalf("Verify on the bound transfer = %v, want nil", err)
	}
	if err := v.AssertSame(tx); err != nil {
		t.Fatalf("AssertSame on the same transaction = %v, want nil", err)
	}
}

// ── constructor: every rejection is a DENY, none is a silent narrowing ──────

func TestNewBoundPayment_Rejections(t *testing.T) {
	good := Binding{
		ChainID:    ArcTestnetChainID,
		Asset:      boundAsset.AccountID32(),
		PayTo:      boundPayTo.AccountID32(),
		Payer:      boundPayer.AccountID32(),
		Amount:     big.NewInt(boundMicroUSDC),
		Nonce:      boundNonce,
		MaxGasCost: new(big.Int).Set(testMaxGasCost),
	}
	dirty := boundPayTo.AccountID32()
	dirty[0] = 1
	var zeroID [AccountIDLen]byte

	cases := []struct {
		name    string
		mutate  func(*Binding)
		wantErr error
	}{
		{"dirty asset identifier", func(b *Binding) { b.Asset = dirty }, ErrDirtyAccountID},
		{"dirty payTo identifier", func(b *Binding) { b.PayTo = dirty }, ErrDirtyAccountID},
		{"dirty payer identifier", func(b *Binding) { b.Payer = dirty }, ErrDirtyAccountID},
		{"zero asset", func(b *Binding) { b.Asset = zeroID }, ErrUnsetAddress},
		{"zero payTo", func(b *Binding) { b.PayTo = zeroID }, ErrUnsetAddress},
		{"unset payer", func(b *Binding) { b.Payer = zeroID }, ErrUnsetAddress},
		{"nil amount", func(b *Binding) { b.Amount = nil }, ErrAmountRange},
		{"negative amount", func(b *Binding) { b.Amount = big.NewInt(-1) }, ErrAmountRange},
		{"amount past u128", func(b *Binding) {
			b.Amount = new(big.Int).Lsh(big.NewInt(1), boundAmountBits)
		}, ErrAmountRange},
		{"nil gas ceiling", func(b *Binding) { b.MaxGasCost = nil }, ErrGasCostRange},
		{"negative gas ceiling", func(b *Binding) { b.MaxGasCost = big.NewInt(-1) }, ErrGasCostRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bind := good
			c.mutate(&bind)
			if _, err := NewBoundPayment(bind); !errors.Is(err, c.wantErr) {
				t.Fatalf("got %v, want %v", err, c.wantErr)
			}
		})
	}
}

// A BoundPayment that never went through the constructor must be useless.
func TestVerify_RejectsUnconstructedBoundPayment(t *testing.T) {
	tx, _ := validPair(t)
	if _, err := Verify(tx, BoundPayment{}); !errors.Is(err, ErrNotBound) {
		t.Fatalf("got %v, want ErrNotBound", err)
	}
}

func TestVerified_ZeroValueFailsClosed(t *testing.T) {
	tx, _ := validPair(t)
	var v Verified
	if err := v.AssertSame(tx); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("got %v, want ErrNotVerified", err)
	}
}

// ── §A.4 field-flip suite: one case per assertion, one sentinel per case ────

func TestVerify_FieldFlips(t *testing.T) {
	cases := []struct {
		name    string
		assert  int
		mutate  func(*Transaction)
		wantErr error
	}{
		{"1: legacy transaction", 1, func(tx *Transaction) { tx.Type = 0 }, ErrUnsupportedTxType},
		{"1: EIP-2930 access-list transaction", 1, func(tx *Transaction) { tx.Type = 1 }, ErrUnsupportedTxType},
		{"1: EIP-4844 blob transaction", 1, func(tx *Transaction) { tx.Type = 3 }, ErrUnsupportedTxType},
		{"1: EIP-7702 set-code transaction", 1, func(tx *Transaction) { tx.Type = 4 }, ErrUnsupportedTxType},

		{"2: access list present", 2, func(tx *Transaction) { tx.AccessListLen = 1 }, ErrAccessListPresent},
		// The bound transfer executes exactly as authorized while the same
		// signed payload installs attacker code at the payer's own EOA. Nothing
		// in `to`/`value`/`data` can see it — only refusing the field can.
		{"2: EIP-7702 authorization smuggled alongside a bound transfer", 2,
			func(tx *Transaction) { tx.AuthorizationListLen = 1 }, ErrAuthorizationListPresent},
		{"2: blob hashes present", 2, func(tx *Transaction) { tx.BlobHashLen = 1 }, ErrBlobHashesPresent},

		{"3: wrong chain id", 3, func(tx *Transaction) { tx.ChainID = 1 }, ErrChainIDMismatch},
		{"3: chain id off by one", 3, func(tx *Transaction) { tx.ChainID = ArcTestnetChainID + 1 }, ErrChainIDMismatch},

		{"4: a second transaction from one authorization", 4,
			func(tx *Transaction) { tx.Nonce = boundNonce + 1 }, ErrNonceMismatch},

		{"5: contract creation", 5, func(tx *Transaction) { tx.To = nil }, ErrContractCreation},
		{"5: call routed through another contract", 5, func(tx *Transaction) {
			m := MustParseAddress("0x522fAf9A91c41c443c66765030741e4AaCe147D0") // Arc's Multicall3From
			tx.To = &m
		}, ErrAssetMismatch},
		{"5: call sent straight to the recipient", 5, func(tx *Transaction) {
			r := boundPayTo
			tx.To = &r
		}, ErrAssetMismatch},

		{"6: native value smuggled alongside the payload", 6, func(tx *Transaction) {
			tx.Value = new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		}, ErrNonZeroValue},
		{"6: one unit of native value", 6, func(tx *Transaction) { tx.Value = big.NewInt(1) }, ErrNonZeroValue},

		{"7: fee cap raised past the ceiling", 7, func(tx *Transaction) {
			tx.MaxFeePerGas = new(big.Int).Add(testMaxFeePerGas, big.NewInt(1))
		}, ErrGasCeilingExceeded},
		{"7: gas limit raised past the ceiling", 7, func(tx *Transaction) {
			tx.GasLimit = testGasLimit + 1
		}, ErrGasCeilingExceeded},
		{"7: 600 USDC of fee alongside a 1 USDC payment", 7, func(tx *Transaction) {
			tx.MaxFeePerGas = new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)
		}, ErrGasCeilingExceeded},
		{"7: negative fee cap", 7, func(tx *Transaction) { tx.MaxFeePerGas = big.NewInt(-1) }, ErrGasCeilingExceeded},

		{"8: signer left unset", 8, func(tx *Transaction) { tx.Signer = Address{} }, ErrUnsetAddress},
		{"8: signed by the wrong account", 8, func(tx *Transaction) { tx.Signer = attacker }, ErrPayerMismatch},

		{"9: calldata tail appended", 9, func(tx *Transaction) {
			tx.Data = append(append([]byte{}, tx.Data...), 0xde, 0xad)
		}, ErrCalldataLength},
		{"9: calldata truncated", 9, func(tx *Transaction) { tx.Data = tx.Data[:TransferCalldataLen-1] }, ErrCalldataLength},
		{"9: empty calldata", 9, func(tx *Transaction) { tx.Data = nil }, ErrCalldataLength},

		{"10: approve instead of transfer", 10, func(tx *Transaction) {
			d := append([]byte{}, tx.Data...)
			copy(d[:4], []byte{0x09, 0x5e, 0xa7, 0xb3})
			tx.Data = d
		}, ErrNotTransfer},
		{"10: dirty high bytes in the address word", 10, func(tx *Transaction) {
			d := append([]byte{}, tx.Data...)
			d[addrWordOff] = 0xff
			tx.Data = d
		}, ErrDirtyAddressWord},

		{"11: recipient redirected", 11, func(tx *Transaction) {
			d, _ := EncodeTransfer(attacker, big.NewInt(boundMicroUSDC))
			tx.Data = d
		}, ErrDestinationMismatch},

		{"12: amount inflated", 12, func(tx *Transaction) {
			d, _ := EncodeTransfer(boundPayTo, big.NewInt(boundMicroUSDC*1000))
			tx.Data = d
		}, ErrAmountMismatch},
		{"12: amount reduced", 12, func(tx *Transaction) {
			d, _ := EncodeTransfer(boundPayTo, big.NewInt(1))
			tx.Data = d
		}, ErrAmountMismatch},

		{"missing fee cap is not read as zero", 0, func(tx *Transaction) { tx.MaxFeePerGas = nil }, ErrMissingField},
		{"missing value is not read as zero", 0, func(tx *Transaction) { tx.Value = nil }, ErrMissingField},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, b := validPair(t)
			c.mutate(&tx)
			_, err := Verify(tx, b)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("assertion %d: got %v, want %v", c.assert, err, c.wantErr)
			}
		})
	}
}

// The fee ceiling is inclusive: spending exactly the ceiling is authorized.
func TestVerify_GasCeilingIsInclusive(t *testing.T) {
	tx, b := validPair(t)
	if _, err := Verify(tx, b); err != nil {
		t.Fatalf("cost exactly at the ceiling: got %v, want nil", err)
	}
}

func TestVerify_ZeroAmountIsBoundLikeAnyOther(t *testing.T) {
	tx, _ := validPair(t)
	b, err := NewBoundPayment(Binding{
		ChainID: ArcTestnetChainID, Asset: boundAsset.AccountID32(),
		PayTo: boundPayTo.AccountID32(), Payer: boundPayer.AccountID32(),
		Amount: big.NewInt(0), Nonce: boundNonce, MaxGasCost: new(big.Int).Set(testMaxGasCost),
	})
	if err != nil {
		t.Fatalf("NewBoundPayment: %v", err)
	}
	if _, err := Verify(tx, b); !errors.Is(err, ErrAmountMismatch) {
		t.Fatalf("got %v, want ErrAmountMismatch", err)
	}
	tx.Data, _ = EncodeTransfer(boundPayTo, big.NewInt(0))
	if _, err := Verify(tx, b); err != nil {
		t.Fatalf("zero-amount bound transfer: got %v, want nil", err)
	}
}

// ── the verdict must not go stale ───────────────────────────────────────────

func TestVerified_SurvivesCallerMutation(t *testing.T) {
	tx, b := validPair(t)
	// A caller-held Value the guard would have to copy to be safe from.
	val := big.NewInt(0)
	tx.Value = val
	// Extra capacity so an append extends the SAME backing array — the case a
	// slice-header copy would not protect against.
	buf := make([]byte, 0, 128)
	buf = append(buf, tx.Data...)
	tx.Data = buf

	v, err := Verify(tx, b)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Now move everything the caller still holds a handle to.
	val.SetString("1000000000000000000000", 10) // 1000 USDC, natively
	tx.Data = append(tx.Data, 0xde, 0xad)
	tx.GasLimit = 30_000_000
	*tx.To = attacker

	got := v.Transaction()
	if got.Value.Sign() != 0 {
		t.Fatalf("verified value moved to %s", got.Value)
	}
	if len(got.Data) != TransferCalldataLen {
		t.Fatalf("verified calldata grew to %d bytes", len(got.Data))
	}
	if got.GasLimit != testGasLimit {
		t.Fatalf("verified gasLimit changed to %d", got.GasLimit)
	}
	if !got.To.Equal(boundAsset) {
		t.Fatalf("verified `to` changed to %s", got.To.Hex())
	}
	// And the mutated transaction must no longer match the verdict.
	if err := v.AssertSame(tx); !errors.Is(err, ErrPostSignDivergence) {
		t.Fatalf("AssertSame on the mutated transaction: got %v, want ErrPostSignDivergence", err)
	}
}

func TestAssertSame_CatchesEveryPostSignChange(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Transaction)
	}{
		{"type", func(tx *Transaction) { tx.Type = 3 }},
		{"chain id", func(tx *Transaction) { tx.ChainID++ }},
		{"nonce", func(tx *Transaction) { tx.Nonce++ }},
		{"gas limit", func(tx *Transaction) { tx.GasLimit++ }},
		{"fee cap", func(tx *Transaction) { tx.MaxFeePerGas = big.NewInt(1) }},
		{"to", func(tx *Transaction) { a := attacker; tx.To = &a }},
		{"to removed", func(tx *Transaction) { tx.To = nil }},
		{"value", func(tx *Transaction) { tx.Value = big.NewInt(1) }},
		{"calldata", func(tx *Transaction) { tx.Data, _ = EncodeTransfer(attacker, big.NewInt(1)) }},
		{"access list", func(tx *Transaction) { tx.AccessListLen = 1 }},
		{"authorization list", func(tx *Transaction) { tx.AuthorizationListLen = 1 }},
		{"blob hashes", func(tx *Transaction) { tx.BlobHashLen = 1 }},
		{"recovered sender", func(tx *Transaction) { tx.Signer = attacker }},
		{"nil fee cap", func(tx *Transaction) { tx.MaxFeePerGas = nil }},
		{"nil value", func(tx *Transaction) { tx.Value = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, b := validPair(t)
			v, err := Verify(tx, b)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			after, _ := validPair(t)
			c.mutate(&after)
			if err := v.AssertSame(after); !errors.Is(err, ErrPostSignDivergence) {
				t.Fatalf("got %v, want ErrPostSignDivergence", err)
			}
		})
	}
}

// ── property: authority never widens ────────────────────────────────────────
//
// Exhaustive over every subset of the bound dimensions, with randomized
// corruption values: Verify returns nil IF AND ONLY IF no dimension was
// corrupted. The oracle is "did we corrupt anything", which is independent of
// the guard's field-by-field logic — so this cannot pass by restating the
// implementation.

const propDimensions = 15

func corrupt(t *testing.T, rng *rand.Rand, dim int, tx *Transaction) {
	t.Helper()
	randAddr := func() Address {
		var a Address
		for a.IsZero() {
			rng.Read(a[:])
		}
		return a
	}
	cur, decErr := DecodeTransfer(tx.Data)
	reencode := func(to Address, amount *big.Int) {
		d, err := EncodeTransfer(to, amount)
		if err != nil {
			t.Fatalf("EncodeTransfer: %v", err)
		}
		tx.Data = d
	}

	switch dim {
	case 0: // envelope type
		for {
			v := uint8(rng.Intn(256))
			if v != TxTypeDynamicFee {
				tx.Type = v
				break
			}
		}
	case 1:
		tx.AccessListLen = rng.Intn(4) + 1
	case 2:
		tx.AuthorizationListLen = rng.Intn(4) + 1
	case 3:
		tx.BlobHashLen = rng.Intn(4) + 1
	case 4: // chain id
		tx.ChainID = ArcTestnetChainID + uint64(rng.Int63n(1<<40)) + 1
	case 5: // nonce
		tx.Nonce = boundNonce + uint64(rng.Int63n(1<<20)) + 1
	case 6: // call target
		if rng.Intn(4) == 0 {
			tx.To = nil
		} else {
			a := randAddr()
			tx.To = &a
		}
	case 7: // native value
		tx.Value = new(big.Int).SetInt64(rng.Int63n(1<<62) + 1)
	case 8: // fee ceiling
		if rng.Intn(2) == 0 {
			tx.GasLimit = testGasLimit + uint64(rng.Int63n(1<<20)) + 1
		} else {
			tx.MaxFeePerGas = new(big.Int).Add(testMaxFeePerGas, big.NewInt(rng.Int63n(1<<40)+1))
		}
	case 9: // signer
		if rng.Intn(8) == 0 {
			tx.Signer = Address{} // unset
		} else {
			tx.Signer = randAddr()
		}
	case 10: // calldata length
		if rng.Intn(2) == 0 {
			tx.Data = append(append([]byte{}, tx.Data...), byte(rng.Intn(256)))
		} else if len(tx.Data) > 0 {
			tx.Data = tx.Data[:len(tx.Data)-1]
		}
	case 11: // selector
		d := append([]byte{}, tx.Data...)
		if len(d) >= 4 {
			for {
				var s [4]byte
				rng.Read(s[:])
				if s != transferSelector {
					copy(d[:4], s[:])
					break
				}
			}
		}
		tx.Data = d
	case 12: // address word padding
		d := append([]byte{}, tx.Data...)
		if len(d) >= addrOff {
			d[addrWordOff+rng.Intn(addrOff-addrWordOff)] = byte(rng.Intn(255) + 1)
		}
		tx.Data = d
	case 13: // recipient
		if decErr == nil {
			reencode(randAddr(), cur.Amount)
		}
	case 14: // amount
		if decErr == nil {
			reencode(cur.To, new(big.Int).Add(cur.Amount, big.NewInt(rng.Int63n(1<<40)+1)))
		}
	}
}

func TestVerify_Property_NeverWidens(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	b := mustBound(t)
	for mask := 0; mask < 1<<propDimensions; mask++ {
		tx, _ := validPair(t)
		// Randomized order so no dimension is always applied last (later
		// dimensions rewrite calldata built by earlier ones).
		order := rng.Perm(propDimensions)
		for _, dim := range order {
			if mask&(1<<dim) != 0 {
				corrupt(t, rng, dim, &tx)
			}
		}
		_, err := Verify(tx, b)
		if mask == 0 {
			if err != nil {
				t.Fatalf("uncorrupted pair rejected: %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("mask %015b (order %v) widened authority: Verify returned nil for a corrupted transaction\n%+v", mask, order, tx)
		}
	}
}

func FuzzVerify(f *testing.F) {
	f.Add(uint8(TxTypeDynamicFee), uint64(ArcTestnetChainID), uint64(boundNonce), uint64(testGasLimit),
		uint64(0), uint64(boundMicroUSDC), []byte(nil))
	f.Fuzz(func(t *testing.T, typ uint8, chainID, nonce, gasLimit, value, amount uint64, data []byte) {
		to := boundAsset
		tx := Transaction{
			Type:         typ,
			ChainID:      chainID,
			Nonce:        nonce,
			GasLimit:     gasLimit,
			MaxFeePerGas: new(big.Int).Set(testMaxFeePerGas),
			To:           &to,
			Value:        new(big.Int).SetUint64(value),
			Data:         data,
			Signer:       boundPayer,
		}
		b := mustBound(t)
		v, err := Verify(tx, b)
		if err != nil {
			return
		}
		// An ALLOW is only ever correct for exactly the bound transfer.
		if typ != TxTypeDynamicFee || chainID != ArcTestnetChainID || nonce != boundNonce || value != 0 {
			t.Fatalf("accepted type=%d chainID=%d nonce=%d value=%d", typ, chainID, nonce, value)
		}
		cost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), testMaxFeePerGas)
		if cost.Cmp(testMaxGasCost) > 0 {
			t.Fatalf("accepted fee cost %s over ceiling %s", cost, testMaxGasCost)
		}
		want, err := EncodeTransfer(boundPayTo, big.NewInt(boundMicroUSDC))
		if err != nil {
			t.Fatalf("EncodeTransfer: %v", err)
		}
		if string(data) != string(want) {
			t.Fatalf("accepted calldata %x, only %x is bound", data, want)
		}
		if err := v.AssertSame(tx); err != nil {
			t.Fatalf("AssertSame on the verified transaction: %v", err)
		}
		_ = amount
	})
}

// The accessors exist so a settlement command can build and display the
// transaction from the binding rather than from its own idea of the payment.
// They must return copies: a caller that mutates what it reads back must not be
// able to move the bound payment.
func TestBoundPayment_AccessorsReturnCopies(t *testing.T) {
	b := mustBound(t)

	if b.ChainID() != ArcTestnetChainID {
		t.Fatalf("ChainID() = %d", b.ChainID())
	}
	if b.Nonce() != boundNonce {
		t.Fatalf("Nonce() = %d", b.Nonce())
	}
	if !b.Asset().Equal(boundAsset) || !b.PayTo().Equal(boundPayTo) || !b.Payer().Equal(boundPayer) {
		t.Fatal("address accessor returned the wrong account")
	}

	amt := b.Amount()
	amt.SetInt64(1)
	if b.Amount().Int64() != boundMicroUSDC {
		t.Fatal("mutating the result of Amount() moved the bound amount")
	}
	gas := b.MaxGasCost()
	gas.SetInt64(1)
	if b.MaxGasCost().Cmp(testMaxGasCost) != 0 {
		t.Fatal("mutating the result of MaxGasCost() moved the bound ceiling")
	}

	tx, _ := validPair(t)
	v, err := Verify(tx, b)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := v.BoundPayment(); got.Amount().Int64() != boundMicroUSDC || !got.PayTo().Equal(boundPayTo) {
		t.Fatal("Verified.BoundPayment() did not carry the payment that was verified")
	}
}

//go:build !race

package evm

import (
	"math/big"
	"sync"
	"testing"
)

// A concurrent mutation of a caller-owned *big.Int, between the constructor
// validating it and the constructor storing it, must not seat an unvalidated
// value in the returned BoundPayment.
//
// Binding.Amount and Binding.MaxGasCost are pointers into memory the caller
// still owns, and big.Int is mutable. This test stresses the window between
// validation and storage: a goroutine flips the sign of the shared big.Int
// while NewBoundPayment runs, and the test asserts every payment handed back
// carries a positive value, which the range check requires. That holds
// absolutely only when the validated snapshot IS the stored value.
//
// Excluded under -race because the mutation is deliberately unsynchronized.
// It is panic-safe regardless: the two source values share magnitude and
// slice shape (abs {100000}, len==cap==1), so a torn read can only ever
// observe +100000 or -100000, never a malformed big.Int.
func TestNewBoundPayment_UsesItsOwnCopies(t *testing.T) {
	fields := []struct {
		name string
		set  func(*Binding, *big.Int)
		get  func(BoundPayment) *big.Int
	}{
		{"Amount", func(b *Binding, v *big.Int) { b.Amount = v }, BoundPayment.Amount},
		{"MaxGasCost", func(b *Binding, v *big.Int) { b.MaxGasCost = v }, BoundPayment.MaxGasCost},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			pos := big.NewInt(100_000)
			neg := new(big.Int).Neg(big.NewInt(100_000)) // abs {100000}, neg = true
			shared := new(big.Int).Set(pos)

			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						*shared = *neg
						*shared = *pos
					}
				}
			}()

			const iters = 300_000
			leaked := 0
			for i := 0; i < iters; i++ {
				b := Binding{
					ChainID:    ArcTestnetChainID,
					Asset:      boundAsset.AccountID32(),
					PayTo:      boundPayTo.AccountID32(),
					Payer:      boundPayer.AccountID32(),
					Amount:     big.NewInt(boundMicroUSDC),
					Nonce:      boundNonce,
					MaxGasCost: new(big.Int).Set(testMaxGasCost),
				}
				f.set(&b, shared)
				bp, err := NewBoundPayment(b)
				if err != nil {
					continue // the snapshot caught a non-positive value and refused it -- correct
				}
				if f.get(bp).Sign() <= 0 {
					leaked++
				}
			}
			close(stop)
			wg.Wait()

			if leaked > 0 {
				t.Fatalf("%s: %d of %d returned bound payments carried a non-positive %s that was never validated",
					f.name, leaked, iters, f.name)
			}
		})
	}
}

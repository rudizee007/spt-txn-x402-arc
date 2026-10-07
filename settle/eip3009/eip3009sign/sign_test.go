//go:build arc

package eip3009sign

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

var (
	now      = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	usdc     = evm.MustParseAddress("0x3600000000000000000000000000000000000000")
	merchant = evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d")
)

// Fixed test keys: generated for this suite, holding nothing.
func testKey(t *testing.T, hexSeed string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA(hexSeed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const (
	payerSeed    = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	attackerSeed = "8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f"
)

func bound(t *testing.T, payer evm.Address) eip3009.Bound {
	t.Helper()
	b, err := eip3009.Bind(eip3009.Binding{
		Domain: eip3009.Domain{Name: "USDC", Version: "2", ChainID: evm.ArcTestnetChainID, VerifyingContract: usdc},
		From:   payer, To: merchant, Value: big.NewInt(500_000), Intent: intent.Digest{7, 7, 7},
		CapabilityExpiry: now.Add(time.Hour), CallExpiry: now.Add(time.Minute), MaxLifetime: 10 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignedByThePayerPasses(t *testing.T) {
	k := testKey(t, payerSeed)
	b := bound(t, evm.Address(crypto.PubkeyToAddress(k.PublicKey)))
	sig, err := Sign(b, k)
	if err != nil {
		t.Fatal(err)
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("v = %d", sig[64])
	}
}

// Assertion 9 on real signatures: each forgery below is refused.
func TestSignatureForgeriesAreRefused(t *testing.T) {
	payerKey, attackerKey := testKey(t, payerSeed), testKey(t, attackerSeed)
	payer := evm.Address(crypto.PubkeyToAddress(payerKey.PublicKey))
	b := bound(t, payer)
	d := b.Digest()

	// Signed by a key other than the payer's.
	wrong, _ := crypto.Sign(d[:], attackerKey)
	wrong[64] += 27
	// Signed by the payer, over a different authorization (another recipient).
	other, err := eip3009.Bind(eip3009.Binding{
		Domain: eip3009.Domain{Name: "USDC", Version: "2", ChainID: evm.ArcTestnetChainID, VerifyingContract: usdc},
		From:   payer, To: evm.MustParseAddress("0x00000000000000000000000000000000000000aa"), Value: big.NewInt(500_000),
		Intent: intent.Digest{7, 7, 7}, CapabilityExpiry: now.Add(time.Hour), CallExpiry: now.Add(time.Minute), MaxLifetime: time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	od := other.Digest()
	overOther, _ := crypto.Sign(od[:], payerKey)
	overOther[64] += 27
	// The payer's valid signature, malleated to high-s: it still recovers to the
	// payer, and must still be refused.
	good, err := Sign(b, payerKey)
	if err != nil {
		t.Fatal(err)
	}
	mall := append([]byte(nil), good...)
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	s := new(big.Int).Sub(n, new(big.Int).SetBytes(good[32:64]))
	s.FillBytes(mall[32:64])
	mall[64] ^= 1 // 27 <-> 28
	// go-ethereum's recovery may itself refuse a high-s signature; the guard's
	// own refusal of high-s is tested without it in the guard package.
	if who, err := Recover(d, mall); err == nil && who != payer {
		t.Fatalf("malleated signature recovered to %s", who.Hex())
	}
	for name, sig := range map[string][]byte{
		"wrong key":                     wrong,
		"payer, over another recipient": overOther,
		"payer, high-s malleation":      mall,
		"truncated":                     good[:64],
		"garbage":                       make([]byte, 65),
	} {
		if err := Check(b, sig); !errors.Is(err, eip3009.ErrViolation) || !strings.Contains(err.Error(), "(9)") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

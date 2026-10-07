//go:build arc

package eip3009

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// Cross-implementation: the guard's digest equals go-ethereum's EIP-712 hash of
// the same typed data, on fixed and random authorizations. With
// EIP3009_WRITE_VECTORS set, the vectors are written for the untagged
// known-answer test.
func TestDigestMatchesGoEthereumTypedData(t *testing.T) {
	r := rand.New(rand.NewSource(3009))
	type vec struct {
		Name, Version, Contract, From, To, Value, ValidAfter, ValidBefore, Nonce, Digest string
		ChainID                                                                          uint64
	}
	var out []vec
	addr := func() evm.Address { var a evm.Address; r.Read(a[:]); return a }
	for i := 0; i < 64; i++ {
		var nonce [32]byte
		r.Read(nonce[:])
		value := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), uint(8+r.Intn(248))))
		value.Add(value, big.NewInt(1))
		names := []string{"USDC", "EURC", "USD Coin", "Ünïcödé €"}
		a := Authorization{
			PrimaryType: PrimaryType,
			Domain:      Domain{Name: names[r.Intn(len(names))], Version: []string{"1", "2", "2.2"}[r.Intn(3)], ChainID: []uint64{5042, 5042002, 1, 1<<63 + 5}[r.Intn(4)], VerifyingContract: addr()},
			From:        addr(), To: addr(), Value: value,
			ValidAfter: big.NewInt(r.Int63n(1 << 40)), ValidBefore: big.NewInt(r.Int63()), Nonce: nonce,
		}
		if i == 0 { // a recognisable fixed case
			a.Domain = Domain{Name: "USDC", Version: "2", ChainID: 5042002, VerifyingContract: usdc}
			a.To, a.Value, a.ValidAfter, a.ValidBefore = merchant, big.NewInt(500_000), big.NewInt(0), big.NewInt(1791460800)
		}
		got := digest(a)
		want := gethDigest(t, a)
		if got != want {
			t.Fatalf("case %d: guard %x, go-ethereum %x", i, got, want)
		}
		out = append(out, vec{a.Domain.Name, a.Domain.Version, a.Domain.VerifyingContract.Hex(), a.From.Hex(), a.To.Hex(),
			a.Value.String(), a.ValidAfter.String(), a.ValidBefore.String(), hex.EncodeToString(a.Nonce[:]), hex.EncodeToString(got[:]), a.Domain.ChainID})
	}
	if p := os.Getenv("EIP3009_WRITE_VECTORS"); p != "" {
		b, _ := json.MarshalIndent(out, "", " ")
		if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func gethDigest(t *testing.T, a Authorization) [32]byte {
	t.Helper()
	td := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {{Name: "name", Type: "string"}, {Name: "version", Type: "string"}, {Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"}},
			"TransferWithAuthorization": {{Name: "from", Type: "address"}, {Name: "to", Type: "address"}, {Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"}, {Name: "validBefore", Type: "uint256"}, {Name: "nonce", Type: "bytes32"}},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{Name: a.Domain.Name, Version: a.Domain.Version,
			ChainId: (*math.HexOrDecimal256)(new(big.Int).SetUint64(a.Domain.ChainID)), VerifyingContract: common.Address(a.Domain.VerifyingContract).Hex()},
		Message: apitypes.TypedDataMessage{
			"from": common.Address(a.From).Hex(), "to": common.Address(a.To).Hex(), "value": a.Value.String(),
			"validAfter": a.ValidAfter.String(), "validBefore": a.ValidBefore.String(), "nonce": "0x" + hex.EncodeToString(a.Nonce[:]),
		},
	}
	h, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], h)
	return out
}

// The low-s rule depends on the group order being exactly secp256k1's.
func TestGroupOrderIsSecp256k1(t *testing.T) {
	if secpN.Cmp(crypto.S256().Params().N) != 0 {
		t.Fatalf("secpN = %x, curve order = %x", secpN, crypto.S256().Params().N)
	}
	if new(big.Int).Lsh(secpHalfN, 1).Cmp(new(big.Int).Sub(secpN, big.NewInt(1))) != 0 {
		t.Fatal("secpHalfN is not floor(n/2)")
	}
}

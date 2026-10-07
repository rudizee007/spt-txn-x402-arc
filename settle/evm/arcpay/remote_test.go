//go:build arc

package arcpay

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// simProvider plays a wallet provider's sign-transaction endpoint (SPEC-ARC-M3
// §4.2). By default it is honest: it decodes the unsigned transaction, signs
// exactly that, and reports its hash. Each hook turns it hostile in one way.
// Like a provider whose own policy approves everything, it never refuses (C2).
type simProvider struct {
	key    *ecdsa.PrivateKey
	chain  *big.Int
	calls  int
	seen   []byte
	alter  func(*types.DynamicFeeTx)                             // rebuild the transaction before signing
	signer *ecdsa.PrivateKey                                     // sign with another key
	output func(signed *types.Transaction) ([]byte, common.Hash) // replace the answer
	delay  time.Duration
	err    error
}

func (p *simProvider) Address() common.Address { return crypto.PubkeyToAddress(p.key.PublicKey) }

func (p *simProvider) SignTransaction(ctx context.Context, unsigned []byte) ([]byte, common.Hash, error) {
	p.calls++
	p.seen = append([]byte(nil), unsigned...)
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	if p.err != nil {
		return nil, common.Hash{}, p.err
	}
	// Decode the unsigned form the way a provider would: as a transaction
	// with an empty signature.
	tx, err := decodeUnsigned(unsigned)
	if err != nil {
		return nil, common.Hash{}, err
	}
	inner := &types.DynamicFeeTx{ChainID: tx.ChainId(), Nonce: tx.Nonce(), GasTipCap: tx.GasTipCap(), GasFeeCap: tx.GasFeeCap(),
		Gas: tx.Gas(), To: tx.To(), Value: tx.Value(), Data: tx.Data(), AccessList: tx.AccessList()}
	if p.alter != nil {
		p.alter(inner)
	}
	k := p.key
	if p.signer != nil {
		k = p.signer
	}
	signed, err := types.SignNewTx(k, types.LatestSignerForChainID(inner.ChainID), inner)
	if err != nil {
		return nil, common.Hash{}, err
	}
	if p.output != nil {
		raw, h := p.output(signed)
		return raw, h, nil
	}
	raw, _ := signed.MarshalBinary()
	return raw, signed.Hash(), nil
}

// decodeUnsigned reads 0x02 || rlp(9 fields) by appending an empty signature.
func decodeUnsigned(b []byte) (*types.Transaction, error) {
	if len(b) < 2 || b[0] != types.DynamicFeeTxType {
		return nil, errors.New("not a dynamic-fee transaction")
	}
	var f struct {
		ChainID    *big.Int
		Nonce      uint64
		Tip, Fee   *big.Int
		Gas        uint64
		To         *common.Address
		Value      *big.Int
		Data       []byte
		AccessList types.AccessList
	}
	if err := rlpDecode(b[1:], &f); err != nil {
		return nil, err
	}
	return types.NewTx(&types.DynamicFeeTx{ChainID: f.ChainID, Nonce: f.Nonce, GasTipCap: f.Tip, GasFeeCap: f.Fee, Gas: f.Gas,
		To: f.To, Value: f.Value, Data: f.Data, AccessList: f.AccessList}), nil
}

func remoteSetup(t *testing.T) (*simProvider, Config, Payment, func() int) {
	t.Helper()
	fake, cfg, p := setup(t)
	prov := &simProvider{key: cfg.Key, chain: new(big.Int).SetUint64(cfg.Net.ChainID)}
	cfg.Key = nil
	cfg.Remote = prov
	return prov, cfg, p, func() int { return len(fake.Broadcasts()) }
}

func TestUnsignedBytesHashToTheSigningHash(t *testing.T) {
	net := evm.ArcTestnet()
	plan := NewPlan(net, common.Address(rcpt), common.HexToAddress("0x1111111111111111111111111111111111111111"), big.NewInt(500_000), 7, big.NewInt(2e9), big.NewInt(1e9))
	plan.GasLimit = 60_000
	tx, err := plan.Build()
	if err != nil {
		t.Fatal(err)
	}
	u, err := UnsignedBytes(tx)
	if err != nil {
		t.Fatal(err)
	}
	if common.BytesToHash(crypto.Keccak256(u)) != NewSigner(net).Hash(tx) {
		t.Fatal("the unsigned serialization does not hash to go-ethereum's signing hash")
	}
}

func TestRemote_HonestProviderSettlesThroughTheGuard(t *testing.T) {
	prov, cfg, p, sent := remoteSetup(t)
	var hookHash common.Hash
	p.BeforeSign = func(h common.Hash) error { hookHash = h; return nil }
	res, err := Settle(context.Background(), cfg, p)
	if err != nil {
		t.Fatalf("honest remote settlement failed: %v", err)
	}
	if prov.calls != 1 || sent() != 1 {
		t.Fatalf("provider calls %d, broadcasts %d", prov.calls, sent())
	}
	if res.SigningHash == (common.Hash{}) || res.SigningHash != hookHash || common.BytesToHash(crypto.Keccak256(prov.seen)) != res.SigningHash {
		t.Fatal("the signing hash given to BeforeSign is not the hash of what the provider was asked to sign")
	}
}

// §4.2 step 4: every way a provider can return something other than the
// transaction it was asked to sign is refused, and nothing is broadcast.
func TestRemote_HostileProviderIsRefused(t *testing.T) {
	stranger, _ := crypto.GenerateKey()
	other := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	cases := map[string]func(*simProvider){
		"re-addressed to another recipient": func(p *simProvider) {
			p.alter = func(tx *types.DynamicFeeTx) {
				tx.Data = append(append([]byte(nil), tx.Data[:16]...), append(other.Bytes(), tx.Data[36:]...)...)
			}
		},
		"amount raised": func(p *simProvider) {
			p.alter = func(tx *types.DynamicFeeTx) { d := append([]byte(nil), tx.Data...); d[67]++; tx.Data = d }
		},
		"native value added": func(p *simProvider) { p.alter = func(tx *types.DynamicFeeTx) { tx.Value = big.NewInt(1) } },
		"fee cap raised": func(p *simProvider) {
			p.alter = func(tx *types.DynamicFeeTx) { tx.GasFeeCap = new(big.Int).Mul(tx.GasFeeCap, big.NewInt(10)) }
		},
		"nonce changed": func(p *simProvider) { p.alter = func(tx *types.DynamicFeeTx) { tx.Nonce++ } },
		"other chain": func(p *simProvider) {
			p.alter = func(tx *types.DynamicFeeTx) { tx.ChainID = new(big.Int).SetUint64(evm.ArcMainnetChainID) }
		},
		"access list added": func(p *simProvider) {
			p.alter = func(tx *types.DynamicFeeTx) { tx.AccessList = types.AccessList{{Address: other}} }
		},
		"signed by another key": func(p *simProvider) { p.signer = stranger },
		"reported hash differs": func(p *simProvider) {
			p.output = func(s *types.Transaction) ([]byte, common.Hash) {
				raw, _ := s.MarshalBinary()
				return raw, common.Hash{1}
			}
		},
		"garbage returned": func(p *simProvider) {
			p.output = func(s *types.Transaction) ([]byte, common.Hash) { return []byte{0x02, 0xc0}, common.Hash{} }
		},
		"legacy transaction returned": func(p *simProvider) {
			p.output = func(s *types.Transaction) ([]byte, common.Hash) {
				l, _ := types.SignNewTx(p.key, types.HomesteadSigner{}, &types.LegacyTx{Nonce: s.Nonce(), GasPrice: s.GasFeeCap(), Gas: s.Gas(), To: s.To(), Data: s.Data()})
				raw, _ := l.MarshalBinary()
				return raw, l.Hash()
			}
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			prov, cfg, p, sent := remoteSetup(t)
			mod(prov)
			_, err := Settle(context.Background(), cfg, p)
			if !errors.Is(err, ErrViolation) {
				t.Fatalf("accepted or wrong class: %v", err)
			}
			if prov.calls != 1 || sent() != 0 {
				t.Fatalf("provider calls %d, broadcasts %d", prov.calls, sent())
			}
		})
	}
}

// The provider is never asked to sign what the guard refuses (C2: its own policy
// approving everything changes nothing), and nothing runs if the correlation
// record cannot be written.
func TestRemote_ProviderNeverSeesARefusedPayment(t *testing.T) {
	prov, cfg, p, sent := remoteSetup(t)
	_, err := SettleWithDemo(context.Background(), cfg, p, Demo{Tamper: func(pl *Plan) { pl.NativeValue = big.NewInt(1) }, Label: "native value"})
	if !errors.Is(err, ErrViolation) || prov.calls != 0 || sent() != 0 {
		t.Fatalf("tampered plan: err=%v calls=%d broadcasts=%d", err, prov.calls, sent())
	}
	prov2, cfg2, p2, sent2 := remoteSetup(t)
	p2.BeforeSign = func(common.Hash) error { return errors.New("correlation file not writable") }
	_, err = Settle(context.Background(), cfg2, p2)
	if !errors.Is(err, ErrUnavailable) || prov2.calls != 0 || sent2() != 0 {
		t.Fatalf("BeforeSign failure: err=%v calls=%d broadcasts=%d", err, prov2.calls, sent2())
	}
}

func TestRemote_ProviderFailureAndLateAnswers(t *testing.T) {
	prov, cfg, p, sent := remoteSetup(t)
	prov.err = errors.New("503 from provider")
	if _, err := Settle(context.Background(), cfg, p); !errors.Is(err, ErrUnavailable) || sent() != 0 {
		t.Fatalf("provider error: %v, broadcasts %d", err, sent())
	}
	prov2, cfg2, p2, sent2 := remoteSetup(t)
	prov2.delay = 300 * time.Millisecond
	p2.NotAfter = time.Now().Add(200 * time.Millisecond)
	_, err := Settle(context.Background(), cfg2, p2)
	if err == nil || sent2() != 0 {
		t.Fatalf("an answer after the authorization lapsed was broadcast: %v", err)
	}
}

func TestRemote_ConfigurationIsExactlyOneSigner(t *testing.T) {
	_, cfg, p, sent := remoteSetup(t)
	k, _ := crypto.GenerateKey()
	cfg.Key = k
	if _, err := Settle(context.Background(), cfg, p); !errors.Is(err, ErrViolation) || !strings.Contains(err.Error(), "both") || sent() != 0 {
		t.Fatalf("key and remote together: %v", err)
	}
	_, cfg2, p2, _ := remoteSetup(t)
	if _, err := SettleWithDemo(context.Background(), cfg2, p2, Demo{DecoyKey: k}); !errors.Is(err, ErrViolation) {
		t.Fatalf("decoy key with a remote signer: %v", err)
	}
}

func rlpDecode(b []byte, v interface{}) error { return rlp.DecodeBytes(b, v) }

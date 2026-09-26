//go:build arc

package arcpay

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay/arcpaytest"
)

// These tests drive the real settlement sequence against a fake endpoint, so
// each control is exercised where it runs, not re-implemented beside it.

func setup(t *testing.T) (*arcpaytest.Fake, Config, Payment) {
	t.Helper()
	net := evm.ArcTestnet()
	fake := arcpaytest.New(net.ChainID)
	t.Cleanup(fake.Close)
	c, err := ethclient.Dial(fake.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return fake, Config{Net: net, Client: c, Key: key, MaxFeeMicro: 50_000, ConfirmTimeout: 5 * time.Second}, goodPayment(net)
}

func mustNotSend(t *testing.T, f *arcpaytest.Fake) {
	t.Helper()
	if n := len(f.Broadcasts()); n != 0 {
		t.Fatalf("%d transaction(s) were broadcast", n)
	}
}

func TestRun_HonestEndpointSettlesExactlyTheAuthorizedTransfer(t *testing.T) {
	fake, cfg, p := setup(t)
	res, err := Settle(context.Background(), cfg, p)
	if err != nil {
		t.Fatalf("honest settlement failed: %v", err)
	}
	sent := fake.Broadcasts()
	if len(sent) != 1 {
		t.Fatalf("%d broadcasts", len(sent))
	}
	tx := sent[0]
	want, _ := evm.EncodeTransfer(p.Recipient, big.NewInt(500_000))
	if tx.ChainId().Uint64() != cfg.Net.ChainID || tx.Value().Sign() != 0 || *tx.To() != common.Address(cfg.Net.USDC) ||
		!bytes.Equal(tx.Data(), want) || tx.Type() != 2 || len(tx.AccessList()) != 0 || res.Block != 101 || res.TxHash != tx.Hash() {
		t.Fatalf("broadcast transaction is not the authorized transfer: %+v", tx)
	}
}

func TestRun_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		fake  func(*arcpaytest.Fake)
		pay   func(*Payment)
		demo  func(*Demo, *Config)
		class error
		want  error
	}{
		{name: "endpoint on another chain", fake: func(f *arcpaytest.Fake) { f.ChainID = evm.ArcMainnetChainID },
			class: ErrViolation, want: ErrWrongNetwork},
		{name: "nonce gap", fake: func(f *arcpaytest.Fake) { f.PendingNonce = 5 }, class: ErrViolation},
		{name: "native and ERC-20 views disagree", fake: func(f *arcpaytest.Fake) { f.NativeOverride = big.NewInt(1) },
			class: ErrViolation, want: evm.ErrNativeViewInconsistent},
		{name: "absurd gas estimate", fake: func(f *arcpaytest.Fake) { f.Gas = MaxGasLimit + 1 },
			class: ErrViolation, want: ErrUnboundedGas},
		{name: "estimate fails outside demo mode", fake: func(f *arcpaytest.Fake) { f.EstimateErr = true }, class: ErrUnavailable},
		{name: "no base fee", fake: func(f *arcpaytest.Fake) { f.NoBaseFee = true }, class: ErrUnavailable},
		{name: "insufficient balance", fake: func(f *arcpaytest.Fake) { f.BalanceMicro = 1 }, class: ErrUnavailable},
		{name: "authorization already expired", pay: func(p *Payment) { p.NotAfter = time.Now().Add(-time.Second) },
			class: ErrViolation, want: ErrExpired},
		{name: "expires between checks and signature",
			demo: func(_ *Demo, c *Config) {
				calls := 0
				c.Now = func() time.Time {
					calls++
					if calls > 1 {
						return time.Now().Add(2 * time.Hour)
					}
					return time.Now()
				}
			}, class: ErrViolation, want: ErrExpired},
		{name: "fee cap above ceiling (guard)", demo: func(d *Demo, _ *Config) {
			d.Tamper = func(p *Plan) { p.FeeCap = new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil) }
		}, class: ErrViolation, want: evm.ErrGasCeilingExceeded},
		{name: "native value attached (guard)", demo: func(d *Demo, _ *Config) {
			d.Tamper = func(p *Plan) { p.NativeValue = big.NewInt(1) }
		}, class: ErrViolation, want: evm.ErrNonZeroValue},
		{name: "recipient swapped in the build (guard)", demo: func(d *Demo, _ *Config) {
			d.Tamper = func(p *Plan) { p.Merchant = common.Address(stranger) }
		}, class: ErrViolation, want: evm.ErrDestinationMismatch},
		{name: "signed by another key (post-sign)", demo: func(d *Demo, _ *Config) {
			k, _ := crypto.GenerateKey()
			d.DecoyKey = k
		}, class: ErrViolation, want: evm.ErrPostSignDivergence},
		{name: "broadcast rejected", fake: func(f *arcpaytest.Fake) { f.SendErr = true }, class: ErrUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake, cfg, p := setup(t)
			if c.fake != nil {
				fake.Set(c.fake)
			}
			if c.pay != nil {
				c.pay(&p)
			}
			var d Demo
			if c.demo != nil {
				c.demo(&d, &cfg)
			}
			_, err := SettleWithDemo(context.Background(), cfg, p, d)
			if !errors.Is(err, c.class) || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("got %v, want %v / %v", err, c.class, c.want)
			}
			mustNotSend(t, fake)
		})
	}
}

// A second endpoint that disagrees on the nonce stops the payment.
func TestRun_NonceCheckEndpoint(t *testing.T) {
	fake, cfg, p := setup(t)
	other := arcpaytest.New(cfg.Net.ChainID)
	defer other.Close()
	other.Set(func(f *arcpaytest.Fake) { f.Nonce = 9 })
	oc, err := ethclient.Dial(other.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer oc.Close()
	cfg.NonceCheck = oc
	if _, err := Settle(context.Background(), cfg, p); !errors.Is(err, ErrNonceDisagrees) {
		t.Fatalf("got %v, want ErrNonceDisagrees", err)
	}
	mustNotSend(t, fake)
}

func TestRun_DryRunSignsNothing(t *testing.T) {
	fake, cfg, p := setup(t)
	if _, err := SettleWithDemo(context.Background(), cfg, p, Demo{DryRun: true}); err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	mustNotSend(t, fake)
}

func TestRun_RevertedIsNotSuccess(t *testing.T) {
	fake, cfg, p := setup(t)
	fake.Set(func(f *arcpaytest.Fake) { f.ReceiptStatus = 0 })
	if _, err := Settle(context.Background(), cfg, p); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a reverted transaction was reported as %v", err)
	}
}

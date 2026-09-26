//go:build arc

package arcpay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

var (
	rcpt     = evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d")
	stranger = evm.MustParseAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
)

func goodPayment(net evm.ArcNetwork) Payment {
	return Payment{
		Authorization:  "1:ab",
		Recipient:      rcpt,
		PayToTransport: evm.AccountIDBase58(rcpt),
		AssetTransport: evm.AccountIDBase58(net.USDC),
		AmountMicro:    "500000",
		NotAfter:       time.Now().Add(time.Hour),
	}
}

// Every input check runs before any key, endpoint or network is touched: with
// no client and no key configured, a bad payment is refused as a VIOLATION,
// and only a good one gets as far as the missing configuration.
func TestSettle_RefusesBadPaymentsBeforeAnythingElse(t *testing.T) {
	net := evm.ArcMainnet()
	cases := []struct {
		name string
		mut  func(*Payment)
		want error
	}{
		{"no authorization", func(p *Payment) { p.Authorization = "" }, ErrNotAuthorized},
		{"no expiry", func(p *Payment) { p.NotAfter = time.Time{} }, ErrNotAuthorized},
		{"zero recipient", func(p *Payment) { p.Recipient = evm.Address{} }, ErrZeroRecipient},
		{"call names another recipient", func(p *Payment) { p.PayToTransport = evm.AccountIDBase58(stranger) }, evm.ErrTransportMismatch},
		{"approved recipient differs from the call", func(p *Payment) { p.Recipient = stranger }, evm.ErrTransportMismatch},
		{"asset is not USDC", func(p *Payment) { p.AssetTransport = evm.AccountIDBase58(stranger) }, ErrAssetNotUSDC},
		{"empty amount", func(p *Payment) { p.AmountMicro = "" }, ErrBadAmount},
		{"zero amount", func(p *Payment) { p.AmountMicro = "0" }, ErrBadAmount},
		{"leading zero", func(p *Payment) { p.AmountMicro = "0500000" }, ErrBadAmount},
		{"sign", func(p *Payment) { p.AmountMicro = "+500000" }, ErrBadAmount},
		{"decimal point", func(p *Payment) { p.AmountMicro = "0.5" }, ErrBadAmount},
		{"overflow", func(p *Payment) { p.AmountMicro = "18446744073709551616" }, ErrBadAmount},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := goodPayment(net)
			c.mut(&p)
			_, err := Settle(context.Background(), Config{Net: net}, p)
			if !errors.Is(err, ErrViolation) || !errors.Is(err, c.want) {
				t.Fatalf("got %v, want a violation wrapping %v", err, c.want)
			}
		})
	}
	_, err := Settle(context.Background(), Config{Net: net}, goodPayment(net))
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("a good payment with no client or key: got %v, want missing configuration", err)
	}
}

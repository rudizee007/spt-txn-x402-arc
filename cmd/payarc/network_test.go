//go:build arc

package main

import (
	"errors"
	"testing"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

func TestCheckMainnetFlags(t *testing.T) {
	const def = "/home/u/.config/spt-txn/arc.key"
	main, test := evm.ArcMainnet(), evm.ArcTestnet()
	cases := []struct {
		name    string
		net     evm.ArcNetwork
		set     map[string]bool
		key     string
		wantErr bool
	}{
		{"testnet takes defaults", test, map[string]bool{}, def, false},
		{"mainnet, nothing named", main, map[string]bool{}, def, true},
		{"mainnet, amount but no key", main, map[string]bool{"amount": true}, def, true},
		{"mainnet, amount, non-default key path not named", main, map[string]bool{"amount": true}, "/k/mainnet.key", true},
		{"mainnet, key but no amount", main, map[string]bool{"key": true}, "/k/mainnet.key", true},
		{"mainnet, default key named explicitly", main, map[string]bool{"key": true, "amount": true}, def, true},
		{"mainnet, own key and amount", main, map[string]bool{"key": true, "amount": true}, "/k/mainnet.key", false},
	}
	for _, c := range cases {
		err := checkMainnetFlags(c.net, c.set, c.key, def)
		if c.wantErr && !errors.Is(err, errMainnetNeedsExplicit) {
			t.Fatalf("%s: got %v, want errMainnetNeedsExplicit", c.name, err)
		}
		if !c.wantErr && err != nil {
			t.Fatalf("%s: got %v, want nil", c.name, err)
		}
	}
}

// The offline selftest must pass on both profiles, not only the default.
func TestSelfTest_BothNetworks(t *testing.T) {
	for _, net := range []evm.ArcNetwork{evm.ArcTestnet(), evm.ArcMainnet()} {
		if rc := runSelfTest(net); rc != 0 {
			t.Fatalf("selftest on %s returned %d", net.Name, rc)
		}
	}
}

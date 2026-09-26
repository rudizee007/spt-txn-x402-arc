//go:build arc

// Command payarc performs a REAL USDC transfer on Arc, gated by the
// SPT-Txn EVM settle guard (docs/SPEC-X402-ARC.md §A.4). It builds the
// transaction, reads every field back off the object that is about to be
// signed, asserts it moves exactly the bound amount of the bound asset to the
// bound recipient under the bound payer's authority and nothing else, and ONLY
// THEN signs. After signing it recovers the sender from the signature and
// re-checks the whole transaction against what was verified. A pre-sign failure
// means no signature at all; a post-sign failure means the signature exists but
// is never broadcast. Either way no funds move.
//
// SCOPE, stated plainly: the bound payment here is declared by the operator on
// the command line, not consumed from a gate ALLOW. This command demonstrates
// that the settlement path cannot deviate from what it was told to pay — which
// is what the -tamper modes exercise. Wiring it to a live gate decision is the
// mcp-gateway path, not this one. Do not describe its output as proof that an
// authorization was enforced end to end.
//
// This is the one path that touches keys and the network, so it is behind the
// `arc` build tag and excluded from the default `go build ./...` and
// `go test ./...`. The signing key stays in its file; it is never read from an
// environment variable, never printed, and never committed.
//
// Build and run (cgo MUST be off — see nocgo.go):
//
//	go get github.com/ethereum/go-ethereum
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -selftest          # offline, no key, no funds
//	# fund your Arc testnet wallet with USDC: https://faucet.circle.com
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc https://rpc.testnet.arc.io -amount 100000
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc ... -to 0x… -amount 100000
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc ... -tamper value   # guard refuses to sign
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -tamper list             # every adversarial mode
//	# Arc MAINNET moves real USDC and is never a default; it must be named:
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc -network mainnet -rpc https://rpc.mainnet.arc.io \
//	    -key ~/.config/spt-txn/arc-mainnet.key -amount 10000     # see docs/RUNBOOK-ARC.md §M
//
// Nothing here is externally audited and nothing is in production.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// The settlement sequence (selector differential, chain id, balances, nonce,
// fees, binding, guard, sign, post-sign re-check, broadcast, confirm) lives in
// settle/evm/arcpay, shared with cmd/arc-gateway. This command supplies the
// operator's payment, prints what happens, and drives the adversarial modes.

func defaultKeyPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		// Not a warning: an empty home turns the default into a RELATIVE path
		// resolved against the working directory, so a settlement could read a
		// key from wherever it happened to be started.
		return "", fmt.Errorf("cannot determine the home directory (%v); pass -key explicitly", err)
	}
	return filepath.Join(h, ".config", "spt-txn", "arc.key"), nil
}

func main() {
	defaultKey, keyPathErr := defaultKeyPath()

	networkName := flag.String("network", "testnet", "Arc network: exactly \"testnet\" or \"mainnet\". Mainnet moves real USDC and is never a default")
	rpcURL := flag.String("rpc", "", "Arc JSON-RPC endpoint for the selected -network (REQUIRED; see SPEC-X402-ARC §A.1)")
	keyPath := flag.String("key", defaultKey, "path to a file containing the payer's secp256k1 key as 64 hex characters")
	toStr := flag.String("to", "", "merchant address (0x…); default: pay yourself")
	boundPayTo := flag.String("bound-payto", "", "the payTo identifier as the gate carries it (base58 of the 32-byte account id); when set, it must denote -to")
	amount := flag.Uint64("amount", 100_000, "amount in micro-USDC (100000 = 0.10 USDC)")
	maxFee := flag.Uint64("max-fee", 50_000, "ceiling on the total transaction fee, in micro-USDC")
	tamper := flag.String("tamper", "", "adversarial demo: build a transaction that trips one §A.4 assertion; `-tamper list` shows them")
	dryRun := flag.Bool("dry-run", false, "build and assert, but never sign or broadcast")
	selfTest := flag.Bool("selftest", false, "offline: build every adversarial transaction and prove each trips its own §A.4 assertion. No key, no network, no funds")
	flag.Parse()

	if *tamper == "list" {
		printTamperModes()
		return
	}
	// Every network-dependent value below comes from this one profile, through
	// the constructors in settle/evm/arcpay (SPEC-X402-ARC §A.1).
	net, err := evm.ArcNetworkByName(*networkName)
	if err != nil {
		fatal(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}
	if *selfTest {
		os.Exit(runSelfTest(net))
	}
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := checkMainnetFlags(net, set, *keyPath, defaultKey); err != nil {
		fatal(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}
	if *rpcURL == "" {
		fatal(fmt.Errorf("%w: -rpc is required and has no default.\n"+
			"  %s.\n"+
			"  Pass it explicitly rather than letting a settlement path silently\n"+
			"  choose a network endpoint for you", arcpay.ErrUnavailable, rpcHint(net)))
	}
	if *keyPath == "" {
		fatal(fmt.Errorf("%w: %w", arcpay.ErrUnavailable, keyPathErr))
	}
	var mode tamperMode
	if *tamper != "" {
		m, ok := tamperModes[*tamper]
		if !ok {
			fatal(fmt.Errorf("%w: unknown -tamper mode %q; run with `-tamper list`", arcpay.ErrViolation, *tamper))
		}
		mode = m
	}

	key, err := arcpay.LoadKey(*keyPath)
	if err != nil {
		fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	merchant := payer
	if *toStr != "" {
		a, err := evm.ParseAddress(*toStr)
		if err != nil {
			fatal(fmt.Errorf("%w: bad -to address: %w", arcpay.ErrViolation, err))
		}
		merchant = common.Address(a)
	}

	if net.Name == "mainnet" {
		fmt.Println("*** ARC MAINNET: this moves real USDC ***")
	}
	fmt.Printf("network:   %s %s (chain id %d)\n", net.Name, net.CAIP2, net.ChainID)
	fmt.Printf("rpc:       %s\n", *rpcURL)
	fmt.Printf("payer:     %s\n", payer)
	fmt.Printf("merchant:  %s\n", merchant)
	fmt.Printf("asset:     %s  (USDC, %d decimals in the ERC-20 view)\n", common.Address(net.USDC), evm.USDCDecimals)
	fmt.Printf("amount:    %d micro-USDC (%s USDC)\n", *amount, arcpay.USDC(new(big.Int).SetUint64(*amount)))
	fmt.Printf("fee cap:   %d micro-USDC\n", *maxFee)

	// The identifier the gate binds is base58 of the widened 32-byte account id
	// (§A.2). If the operator supplies the one the gate actually carried, it is
	// checked against the address we are about to pay: two independent sides,
	// a comparison that can fail. Without it, we only print the encoding.
	transport := evm.AccountIDBase58(evm.Address(merchant))
	if *boundPayTo != "" {
		if err := evm.AssertTransportMatches(evm.Address(merchant), *boundPayTo); err != nil {
			fatal(fmt.Errorf("%w: -bound-payto does not denote -to (%s): %w", arcpay.ErrViolation, merchant, err))
		}
		fmt.Printf("bound payTo: %s  (matches -to)\n\n", *boundPayTo)
	} else {
		fmt.Printf("payTo as the gate would carry it: %s  (not checked; pass -bound-payto to check it)\n\n", transport)
	}

	ctx, cancel := context.WithTimeout(context.Background(), arcpay.DefaultConfirmTimeout+time.Minute)
	defer cancel()
	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		fatal(fmt.Errorf("%w: dial %s: %w", arcpay.ErrUnavailable, *rpcURL, err))
	}
	defer client.Close()

	demo := arcpay.Demo{DryRun: *dryRun}
	if mode.description != "" {
		demo.Label = *tamper + ": " + mode.description
		demo.Tamper = mode.apply
		if mode.postSign {
			k, err := crypto.GenerateKey()
			if err != nil {
				fatal(fmt.Errorf("%w: generate decoy key: %w", arcpay.ErrUnavailable, err))
			}
			demo.DecoyKey = k
		}
	}

	// The operator's command line is this command's authorization; the gateway
	// passes the enforcement point's log locator instead.
	res, err := arcpay.SettleWithDemo(ctx, arcpay.Config{
		Net: net, Client: client, Key: key, MaxFeeMicro: *maxFee, Log: os.Stdout,
	}, arcpay.Payment{
		Authorization:  "operator:payarc",
		Recipient:      evm.Address(merchant),
		PayToTransport: transport,
		AssetTransport: evm.AccountIDBase58(net.USDC),
		AmountMicro:    strconv.FormatUint(*amount, 10),
		// The operator is present; the signature must follow within a minute.
		NotAfter: time.Now().Add(time.Minute),
	}, demo)
	if err != nil {
		fatal(err)
	}
	if *dryRun {
		return
	}

	fmt.Printf("\nSETTLED    %d micro-USDC (%s USDC)\n", *amount, arcpay.USDC(new(big.Int).SetUint64(*amount)))
	fmt.Printf("  payer:    %s\n", res.Payer)
	fmt.Printf("  merchant: %s\n", merchant)
	fmt.Printf("  block:    %d, gas used %d\n", res.Block, res.GasUsed)
	fmt.Printf("  network:  %s (chain id %d)\n", net.CAIP2, net.ChainID)
	fmt.Printf("  tx:       %s%s\n", net.ExplorerTxPrefix, res.TxHash.Hex())
}

// ── adversarial demo modes ──────────────────────────────────────────────────

type tamperMode struct {
	description string
	// wantErr is the sentinel this mode must trip. It lives here so the mapping
	// from "what the attacker did" to "which control caught it" is written down
	// once and checked by -selftest, rather than asserted in prose.
	wantErr error
	// postSign marks a mode the pre-sign guard cannot see, because it changes
	// who signs rather than what is signed.
	postSign bool
	apply    func(*arcpay.Plan)
}

// Every mode trips exactly one assertion, so the demo can show each control
// firing on its own rather than one generic refusal.
var tamperModes = map[string]tamperMode{
	"recipient": {"building the transfer to an ATTACKER address while the bound payTo is the merchant (§A.4.11)",
		evm.ErrDestinationMismatch, false, func(p *arcpay.Plan) {
			p.Merchant = common.Address(evm.MustParseAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"))
		}},
	"amount": {"inflating the transfer 1000x above the bound amount (§A.4.12)",
		evm.ErrAmountMismatch, false, func(p *arcpay.Plan) {
			p.Amount = new(big.Int).Mul(p.Amount, big.NewInt(1000))
		}},
	"value": {"attaching NATIVE USDC to a perfectly bound ERC-20 payload: same funds, second interface (§A.4.6, §A.5.1)",
		evm.ErrNonZeroValue, false, func(p *arcpay.Plan) {
			p.NativeValue = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 1 USDC, natively
		}},
	"chain": {"building for Ethereum mainnet instead of Arc (§A.4.3)",
		evm.ErrChainIDMismatch, false, func(p *arcpay.Plan) {
			p.ChainIDOverride = big.NewInt(1)
		}},
	"nonce": {"reusing the authorization on a second nonce (§A.4.4)",
		evm.ErrNonceMismatch, false, func(p *arcpay.Plan) {
			p.Nonce = p.Nonce + 1
		}},
	"target": {"routing the call through Arc's Multicall3From instead of the USDC contract (§A.4.5)",
		evm.ErrAssetMismatch, false, func(p *arcpay.Plan) {
			a := common.Address(evm.MustParseAddress("0x522fAf9A91c41c443c66765030741e4AaCe147D0"))
			p.ToOverride = &a
		}},
	"selector": {"swapping transfer() for approve(): a standing allowance instead of a payment (§A.4.10)",
		evm.ErrNotTransfer, false, func(p *arcpay.Plan) {
			p.DataOverlay = func(d []byte) []byte {
				out := append([]byte(nil), d...)
				copy(out[:4], []byte{0x09, 0x5e, 0xa7, 0xb3})
				return out
			}
		}},
	"tail": {"appending bytes after the ABI arguments, which Solidity would ignore (§A.4.9)",
		evm.ErrCalldataLength, false, func(p *arcpay.Plan) {
			p.DataOverlay = func(d []byte) []byte { return append(append([]byte(nil), d...), 0xde, 0xad, 0xbe, 0xef) }
		}},
	"padding": {"dirtying the ignored high bytes of the address word (§A.4.10)",
		evm.ErrDirtyAddressWord, false, func(p *arcpay.Plan) {
			p.DataOverlay = func(d []byte) []byte {
				out := append([]byte(nil), d...)
				out[4] = 0xff
				return out
			}
		}},
	"gas": {"raising the fee cap so the FEE dwarfs the payment, in the same asset (§A.4.7, §A.5.3)",
		evm.ErrGasCeilingExceeded, false, func(p *arcpay.Plan) {
			p.FeeCap = new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)
		}},
	"accesslist": {"attaching an EIP-2930 access list the binding never authorized (§A.4.2)",
		evm.ErrAccessListPresent, false, func(p *arcpay.Plan) {
			p.AccessList = types.AccessList{{Address: p.Asset, StorageKeys: []common.Hash{{}}}}
		}},
	"legacy": {"downgrading to a pre-EIP-1559 legacy transaction envelope (§A.4.1)",
		evm.ErrUnsupportedTxType, false, func(p *arcpay.Plan) {
			p.Legacy = true
		}},
	"signer": {"signing a perfectly bound transaction with an unauthorized key: invisible before signing, caught after (§A.4 post-sign)",
		evm.ErrPostSignDivergence, true, func(p *arcpay.Plan) {}},
}

func printTamperModes() {
	fmt.Println("adversarial demo modes, each trips exactly one assertion:")
	for _, n := range sortedModes() {
		leg := "pre-sign "
		if tamperModes[n].postSign {
			leg = "post-sign"
		}
		fmt.Printf("  -tamper %-11s [%s] %s\n", n, leg, tamperModes[n].description)
	}
}

func sortedModes() []string {
	names := make([]string, 0, len(tamperModes))
	for n := range tamperModes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// fatal prints the error, which leads with its decision class (an attack looks
// different from an outage, SPEC-X402 §5), and exits non-zero.
func fatal(err error) {
	msg := strings.TrimSpace(err.Error())
	if !errors.Is(err, arcpay.ErrViolation) && !errors.Is(err, arcpay.ErrUnavailable) {
		msg = "DENY_UNAVAILABLE: " + msg
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", msg)
	os.Exit(1)
}

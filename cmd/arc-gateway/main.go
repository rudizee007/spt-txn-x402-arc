//go:build arc

// Command arc-gateway is an MCP server over stdio that gives an agent one tool,
// authorize_payment, and settles an authorized payment in USDC on Arc
// (docs/SPEC-ARC-GATE.md). Each call is decided by the SPT-Txn enforcement
// point against one capability a human approved; only a recorded ALLOW reaches
// settlement, and settlement runs through the settle/evm pre-sign guard.
//
// Register it with an MCP client, for example:
//
//	{ "mcpServers": { "spt-txn-arc": { "command": "/path/to/arc-gateway",
//	    "args": ["-capability", "cap.json", "-rpc", "https://rpc.testnet.arc.io",
//	             "-key", "pay.key", "-log-key", "log.key", "-log", "decisions.json",
//	             "-checkpoint-key", "checkpoint.key"] } } }
//
// Build with CGO_ENABLED=0 go build -tags arc ./cmd/arc-gateway (see nocgo.go).
// Diagnostics go to stderr; stdout carries only the MCP protocol.
//
// Nothing here is externally audited and nothing is in production.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/mcpgate"
	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

func main() {
	capPath := flag.String("capability", "", "approved capability JSON file (required)")
	rpcURL := flag.String("rpc", "", "Arc JSON-RPC endpoint for the capability's network (required)")
	keyPath := flag.String("key", "", "payment key file, 64 hex characters (required)")
	logKeyPath := flag.String("log-key", "", "log signing key file: an Ed25519 seed, 64 hex characters (required)")
	logPath := flag.String("log", "", "transparency log file; created if absent (required)")
	cpKeyPath := flag.String("checkpoint-key", "", "checkpoint key file, 64 hex characters, not the payment key (required)")
	cpEvery := flag.Int("checkpoint-every", 10, "publish the log head on Arc after this many new decisions")
	maxFee := flag.Uint64("max-fee", 50_000, "ceiling on each payment's total fee, micro-USDC")
	dryRun := flag.Bool("dry-run", false, "run the guard but never sign or broadcast a payment")
	flag.Parse()

	for name, v := range map[string]string{"capability": *capPath, "rpc": *rpcURL, "key": *keyPath,
		"log-key": *logKeyPath, "log": *logPath, "checkpoint-key": *cpKeyPath} {
		if v == "" {
			fatal(fmt.Errorf("%w: -%s is required and has no default", arcpay.ErrUnavailable, name))
		}
	}
	if *cpEvery < 1 {
		fatal(fmt.Errorf("%w: -checkpoint-every must be at least 1", arcpay.ErrViolation))
	}

	cap, err := loadCapability(*capPath, time.Now())
	if err != nil {
		fatal(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}
	payKey, err := arcpay.LoadKey(*keyPath)
	if err != nil {
		fatal(err)
	}
	cpKey, err := arcpay.LoadKey(*cpKeyPath)
	if err != nil {
		fatal(err)
	}
	payAddr, cpAddr := crypto.PubkeyToAddress(payKey.PublicKey), crypto.PubkeyToAddress(cpKey.PublicKey)
	if err := distinctKeys(payAddr, cpAddr); err != nil {
		fatal(err)
	}
	logKey, err := loadEd25519(*logKeyPath)
	if err != nil {
		fatal(err)
	}
	log, err := openLog(*logPath, logKey.Public().(ed25519.PublicKey))
	if err != nil {
		fatal(err)
	}

	ctx := context.Background()
	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		fatal(fmt.Errorf("%w: dial %s: %w", arcpay.ErrUnavailable, *rpcURL, err))
	}
	defer client.Close()
	reported, err := client.ChainID(ctx)
	if err != nil {
		fatal(fmt.Errorf("%w: eth_chainId: %w", arcpay.ErrUnavailable, err))
	}
	if err := arcpay.CheckEndpointChain(cap.Net, reported); err != nil {
		fatal(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}

	used := 0
	asset := evm.AccountIDBase58(cap.Net.USDC)
	enf := &mcpgate.Enforcer{
		Scheme:  "exact",
		Network: cap.Net.CAIP2,
		Allowlist: gate.Allowlist{
			Schemes:  map[string]byte{"exact": 1},
			Networks: map[string]byte{cap.Net.CAIP2: cap.Net.NetworkTag},
		},
		Policy: countingPolicy{
			exact: mcpgate.ExactPayment{Asset: asset, PayTo: evm.AccountIDBase58(cap.Recipient), Resource: cap.Resource, MaxAmount: cap.MaxMicro},
			max:   cap.MaxPayments,
			used:  &used,
		},
		Spend: gate.NewMemSpendLog(),
		Log:   log,
		RKey:  logKey,
		Logf:  func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}

	cfg := arcpay.Config{Net: cap.Net, Client: client, Key: payKey, MaxFeeMicro: *maxFee, Log: os.Stderr}
	settle := func(ctx context.Context, p arcpay.Payment) (arcpay.Result, error) {
		return arcpay.SettleWithDemo(ctx, cfg, p, arcpay.Demo{DryRun: *dryRun})
	}
	if !*dryRun {
		settle = func(ctx context.Context, p arcpay.Payment) (arcpay.Result, error) { return arcpay.Settle(ctx, cfg, p) }
	}

	cp := newCheckpointer(cap.Net, client, cpKey, log, *cpEvery, os.Stderr)
	s := &server{
		cap: cap, enf: enf, settle: settle,
		saveLog: func() error { return log.Save(*logPath) },
		onEntry: cp.maybePublish,
		now:     time.Now, used: &used,
		out: os.Stdout, diag: os.Stderr,
	}

	fmt.Fprintln(os.Stderr, "spt-txn arc-gateway ready (stdio).")
	fmt.Fprintf(os.Stderr, "  network:    %s %s\n", cap.Net.Name, cap.Net.CAIP2)
	fmt.Fprintf(os.Stderr, "  capability: pay <= %s USDC to %s for %q, at most %d payment(s), until %s\n",
		arcpay.USDC(new(big.Int).SetUint64(cap.MaxMicro)), cap.Recipient.Hex(), cap.Resource, cap.MaxPayments, cap.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "  payer:      %s\n  checkpoints from %s every %d decisions\n", payAddr, cpAddr, *cpEvery)
	fmt.Fprintf(os.Stderr, "  log key:    %s (%d entries loaded)\n", hex.EncodeToString(logKey.Public().(ed25519.PublicKey)), log.Len())
	if *dryRun {
		fmt.Fprintln(os.Stderr, "  DRY RUN: the guard runs, nothing is signed or sent")
	}
	s.serve(ctx, os.Stdin)
	cp.publishNow() // clean shutdown: one more checkpoint of the final head
}

// loadEd25519 reads a log signing key: a 32-byte Ed25519 seed as 64 hex
// characters, from a file that passes the same permission checks as every
// other key.
func loadEd25519(path string) (ed25519.PrivateKey, error) {
	if err := arcpay.CheckKeyFile(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", arcpay.ErrUnavailable, path, err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s must hold exactly 64 hex characters (a 32-byte Ed25519 seed)", arcpay.ErrViolation, path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// openLog loads and verifies an existing log, refusing one signed by another
// key, or creates and saves an empty one. Either way the file is writable
// before the first call is accepted.
func openLog(path string, pub ed25519.PublicKey) (*translog.Log, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		l := translog.NewLog(pub)
		if err := l.Save(path); err != nil {
			return nil, fmt.Errorf("%w: create log %s: %w", arcpay.ErrUnavailable, path, err)
		}
		return l, nil
	}
	l, err := translog.LoadLog(path)
	if err != nil {
		return nil, fmt.Errorf("%w: load log %s: %w", arcpay.ErrViolation, path, err)
	}
	if subtle.ConstantTimeCompare(l.PublicKey(), pub) != 1 {
		return nil, fmt.Errorf("%w: log %s was signed by a different key", arcpay.ErrViolation, path)
	}
	if err := l.Save(path); err != nil {
		return nil, fmt.Errorf("%w: log %s is not writable: %w", arcpay.ErrUnavailable, path, err)
	}
	return l, nil
}

func fatal(err error) {
	msg := strings.TrimSpace(err.Error())
	if !errors.Is(err, arcpay.ErrViolation) && !errors.Is(err, arcpay.ErrUnavailable) {
		msg = "DENY_UNAVAILABLE: " + msg
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", msg)
	os.Exit(1)
}

// distinctKeys refuses a checkpoint key that is the payment key: three roles,
// three keys (SPEC-ARC-GATE §5).
func distinctKeys(pay, checkpoint common.Address) error {
	if subtle.ConstantTimeCompare(pay[:], checkpoint[:]) == 1 {
		return fmt.Errorf("%w: the checkpoint key is the payment key; they must be different keys", arcpay.ErrViolation)
	}
	return nil
}

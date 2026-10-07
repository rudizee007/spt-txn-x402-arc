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
//	    "args": ["-capability", "/etc/spt-txn-arc/capability.json",
//	             "-rpc", "https://rpc.testnet.arc.io",
//	             "-key", "/etc/spt-txn-arc/pay.key",
//	             "-log-key", "/etc/spt-txn-arc/log.key",
//	             "-checkpoint-key", "/etc/spt-txn-arc/checkpoint.key",
//	             "-log", "/var/lib/spt-txn-arc/decisions.json",
//	             "-state-dir", "/var/lib/spt-txn-arc/state"] } } }
//
// -log and -state-dir are required and must be absolute paths.
//
// Build with CGO_ENABLED=0 go build -tags arc ./cmd/arc-gateway (see nocgo.go).
// Diagnostics go to stderr; stdout carries only the MCP protocol.
//
// Nothing here is externally audited and nothing is in production.
package main

import (
	"context"
	"crypto/ecdsa"
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
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/circlewallet"
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
	evaluateOnly := flag.Bool("evaluate-only", false, "hold no payment key; offer evaluate_payment, which returns the decision and can never settle (refuses -key and -dry-run)")
	stateDir := flag.String("state-dir", "", "directory for per-capability payment counts and locks, shared by every gateway for a capability (required)")
	verifyRPC := flag.String("verify-rpc", "", "optional second, independent endpoint; the payer's nonce must agree on both (recommended on mainnet)")
	var m3f m3Flags
	m3f.register(flag.CommandLine)
	flag.Parse()

	mode, err := resolveModeM3(*evaluateOnly, *dryRun, *keyPath, flag.Args(), m3f.remote())
	if err != nil {
		fatal(err)
	}
	if err := m3f.validate(mode); err != nil {
		fatal(err)
	}
	for name, v := range map[string]string{"capability": *capPath, "rpc": *rpcURL,
		"log-key": *logKeyPath, "log": *logPath, "checkpoint-key": *cpKeyPath} {
		if v == "" {
			fatal(fmt.Errorf("%w: -%s is required and has no default", arcpay.ErrUnavailable, name))
		}
	}
	if err := checkPathFlags(*logPath, *stateDir); err != nil {
		fatal(err)
	}
	if *cpEvery < 1 {
		fatal(fmt.Errorf("%w: -checkpoint-every must be at least 1", arcpay.ErrViolation))
	}

	cap, capDigest, err := loadCapability(*capPath, time.Now())
	if err != nil {
		fatal(fmt.Errorf("%w: %w", arcpay.ErrViolation, err))
	}
	// In evaluate-only mode no payment key is read at all (§6a).
	var payKey, cpKey *ecdsa.PrivateKey
	var wallet *circlewallet.Wallet
	switch {
	case mode == modeEvaluate:
		cpKey, err = arcpay.LoadKey(*cpKeyPath)
	case m3f.remote():
		if cpKey, err = arcpay.LoadKey(*cpKeyPath); err == nil {
			if wallet, err = m3f.loadCircle(); err == nil {
				err = distinctKeys(wallet.Address(), crypto.PubkeyToAddress(cpKey.PublicKey))
			}
		}
	default:
		payKey, cpKey, err = loadKeys(*keyPath, *cpKeyPath)
	}
	if err != nil {
		fatal(err)
	}
	cpAddr := crypto.PubkeyToAddress(cpKey.PublicKey)
	payer := "none (evaluate-only: no payment key)"
	switch {
	case payKey != nil:
		payer = crypto.PubkeyToAddress(payKey.PublicKey).Hex()
	case wallet != nil:
		payer = wallet.Address().Hex() + " (Circle developer-controlled wallet " + m3f.circleWallet + ")"
	}
	logKey, err := loadEd25519(*logKeyPath)
	if err != nil {
		fatal(err)
	}
	// The lock is taken before the log, the count or the checkpoint record is
	// read, and held until exit (§6).
	st, err := openLogState(*logPath, *stateDir, logKey.Public().(ed25519.PublicKey), capDigest)
	if err != nil {
		fatal(err)
	}
	defer func() { _ = st.close() }()
	log := st.log

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
			used:  &st.used,
		},
		Spend: gate.NewMemSpendLog(),
		Log:   log,
		RKey:  logKey,
		Logf:  func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}

	// settle stays nil in evaluate-only mode: there is nothing to settle with.
	var settle settleFunc
	if mode != modeEvaluate && (!m3f.on() || m3f.rail == railTransfer) {
		cfg := arcpay.Config{Net: cap.Net, Client: client, Key: payKey, MaxFeeMicro: *maxFee, Log: os.Stderr}
		if wallet != nil {
			cfg.Key, cfg.Remote = nil, wallet
		}
		if *verifyRPC != "" {
			vc, err := ethclient.DialContext(ctx, *verifyRPC)
			if err != nil {
				fatal(fmt.Errorf("%w: dial %s: %w", arcpay.ErrUnavailable, *verifyRPC, err))
			}
			defer vc.Close()
			vid, err := vc.ChainID(ctx)
			if err != nil {
				fatal(fmt.Errorf("%w: eth_chainId on %s: %w", arcpay.ErrUnavailable, *verifyRPC, err))
			}
			if err := arcpay.CheckEndpointChain(cap.Net, vid); err != nil {
				fatal(fmt.Errorf("%w: -verify-rpc: %w", arcpay.ErrViolation, err))
			}
			cfg.NonceCheck = vc
		}
		settle = func(ctx context.Context, p arcpay.Payment) (arcpay.Result, error) {
			return arcpay.SettleWithDemo(ctx, cfg, p, arcpay.Demo{DryRun: *dryRun})
		}
		if !*dryRun {
			settle = func(ctx context.Context, p arcpay.Payment) (arcpay.Result, error) { return arcpay.Settle(ctx, cfg, p) }
		}
	}

	cp := st.checkpointer(cap.Net, client, cpKey, *cpEvery, os.Stderr)
	s := &server{
		mode: mode,
		cap:  cap, enf: enf, settle: settle,
		persist: st.save,
		onEntry: cp.maybePublish,
		now:     time.Now, used: &st.used,
		out: os.Stdout, diag: os.Stderr,
	}

	if m3f.on() {
		m, err := m3f.buildM3(mode, st.path, log, logKey, cap.Net, payKey, wallet)
		if err != nil {
			fatal(err)
		}
		defer func() { _ = m.corr.Close() }()
		s.m3 = m
	}

	fmt.Fprintln(os.Stderr, "spt-txn arc-gateway ready (stdio).")
	fmt.Fprintf(os.Stderr, "  network:    %s %s\n", cap.Net.Name, cap.Net.CAIP2)
	fmt.Fprintf(os.Stderr, "  capability: pay <= %s USDC to %s for %q, at most %d payment(s) (%d used), until %s\n",
		arcpay.USDC(new(big.Int).SetUint64(cap.MaxMicro)), cap.Recipient.Hex(), cap.Resource, cap.MaxPayments, st.used, cap.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "  log:        %s\n  state:      %s\n", st.path, st.stateDir)
	fmt.Fprintf(os.Stderr, "  mode:       %s (tool %s)\n", mode, s.toolName())
	fmt.Fprintf(os.Stderr, "  payer:      %s\n  checkpoints from %s every %d decisions\n", payer, cpAddr, *cpEvery)
	fmt.Fprintf(os.Stderr, "  log key:    %s (%d entries loaded)\n", hex.EncodeToString(logKey.Public().(ed25519.PublicKey)), log.Len())
	if s.m3 != nil {
		fmt.Fprintf(os.Stderr, "  M3:         server identity %q, rail %s, signer %s\n", s.m3.identity, s.m3.rail, orNone(m3f.signer))
		fmt.Fprintf(os.Stderr, "  correlation: %s.correlation (%d records, verified against the log)\n", st.path, s.m3.corr.Len())
	}
	switch mode {
	case modeDryRun:
		fmt.Fprintln(os.Stderr, "  DRY RUN: the guard runs, nothing is signed or sent")
	case modeEvaluate:
		fmt.Fprintln(os.Stderr, "  EVALUATE-ONLY: no payment key loaded; no payment can be signed or sent (checkpoints only)")
	}
	serr := s.serve(ctx, os.Stdin)
	cp.publishNow() // one more checkpoint of the last saved head
	if serr != nil {
		fatal(fmt.Errorf("%w: input stream ended with an error: %w", arcpay.ErrUnavailable, serr))
	}
}

// loadEd25519 reads a log signing key: a 32-byte Ed25519 seed as 64 hex
// characters, from a file that passes the same permission checks as every
// other key.
func loadEd25519(path string) (ed25519.PrivateKey, error) {
	resolved, err := arcpay.ResolveKeyFile(path)
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- the path ResolveKeyFile walked and checked, from the
	// operator's command line.
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", arcpay.ErrUnavailable, resolved, err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s must hold exactly 64 hex characters (a 32-byte Ed25519 seed)", arcpay.ErrViolation, resolved)
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

// loadKeys loads the payment and checkpoint keys and refuses the same key in
// both roles.
func loadKeys(payPath, cpPath string) (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	pay, err := arcpay.LoadKey(payPath)
	if err != nil {
		return nil, nil, err
	}
	cp, err := arcpay.LoadKey(cpPath)
	if err != nil {
		return nil, nil, err
	}
	if err := distinctKeys(crypto.PubkeyToAddress(pay.PublicKey), crypto.PubkeyToAddress(cp.PublicKey)); err != nil {
		return nil, nil, err
	}
	return pay, cp, nil
}

// distinctKeys refuses a checkpoint key that is the payment key: three roles,
// three keys (SPEC-ARC-GATE §5).
func distinctKeys(pay, checkpoint common.Address) error {
	if subtle.ConstantTimeCompare(pay[:], checkpoint[:]) == 1 {
		return fmt.Errorf("%w: the checkpoint key is the payment key; they must be different keys", arcpay.ErrViolation)
	}
	return nil
}

// resolveMode fixes the server's mode from its flags (SPEC-ARC-GATE §6a).
// Evaluate-only refuses a payment key and -dry-run; the other modes require a
// payment key.
func resolveMode(evaluateOnly, dryRun bool, keyPath string, extra []string) (string, error) {
	switch {
	case len(extra) > 0:
		// flag stops at the first non-flag argument, so every flag after it,
		// -evaluate-only included, would be silently ignored.
		return "", fmt.Errorf("%w: unexpected argument %q; every flag after it would be ignored", arcpay.ErrViolation, extra[0])
	case evaluateOnly && keyPath != "":
		return "", fmt.Errorf("%w: -evaluate-only holds no payment key; remove -key", arcpay.ErrViolation)
	case evaluateOnly && dryRun:
		return "", fmt.Errorf("%w: -evaluate-only and -dry-run are different modes; choose one", arcpay.ErrViolation)
	case evaluateOnly:
		return modeEvaluate, nil
	case keyPath == "":
		return "", fmt.Errorf("%w: -key is required unless -evaluate-only", arcpay.ErrUnavailable)
	case dryRun:
		return modeDryRun, nil
	}
	return modeLive, nil
}

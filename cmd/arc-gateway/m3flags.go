//go:build arc

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/correlation"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009/eip3009sign"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/circlewallet"
	"github.com/rudizee007/spt-txn-x402-arc/x402v2"
)

// minAuthLifetime is this gateway's OPERATIONAL minimum for
// -max-auth-lifetime on the EIP-3009 rail. It is not an x402 protocol value.
//
// The protocol-side requirement is different and smaller: the x402 reference
// facilitator (x402-foundation/x402 @ 7f2b2f1,
// go/mechanisms/evm/exact/facilitator/eip3009.go) refuses an authorization
// whose validBefore is less than 6 seconds after the moment it verifies it.
// An authorization also has to travel from this gateway, through the agent and
// the resource server, to the facilitator before that check runs. 30 seconds
// is our safety margin over the 6 for that journey, so a signed authorization
// is not already unusable when it arrives. Change it on evidence, not to make
// a test pass.
const minAuthLifetime = 30 * time.Second

// m3Flags are the SPEC-ARC-M3 startup settings. M3 mode is on exactly when
// -server-identity is given; every other M3 flag without it is refused, so a
// half-configured M3 gateway cannot start as an M2 one.
type m3Flags struct {
	identity      string
	rail          string
	signer        string
	maxLife       time.Duration
	domainName    string
	domainVersion string
	circleBaseURL string
	circleWallet  string
	circleAddress string
	circleAPIKey  string // file
	circleSecret  string // file
	circlePubKey  string // file
}

func (f *m3Flags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.identity, "server-identity", "", "SPEC-ARC-M3: the enforcement point's configured server identity (target); turns on M3 mode")
	fs.StringVar(&f.rail, "rail", "", "M3 rail: transfer (ERC-20 transfer, settled here) or eip3009 (x402 exact authorization, submitted by a facilitator)")
	fs.StringVar(&f.signer, "signer", "", "M3 signer: key (-key) or circle (a Circle developer-controlled wallet)")
	fs.DurationVar(&f.maxLife, "max-auth-lifetime", 0, "eip3009: maximum authorization lifetime, at least 30s (an operational minimum, not an x402 value), e.g. 2m (required for -rail eip3009)")
	fs.StringVar(&f.domainName, "eip3009-domain-name", "", "eip3009: the USDC contract's pinned EIP-712 domain name")
	fs.StringVar(&f.domainVersion, "eip3009-domain-version", "", "eip3009: the USDC contract's pinned EIP-712 domain version")
	fs.StringVar(&f.circleBaseURL, "circle-base-url", circlewallet.DefaultBaseURL, "circle: API base URL (https)")
	fs.StringVar(&f.circleWallet, "circle-wallet-id", "", "circle: developer-controlled wallet id")
	fs.StringVar(&f.circleAddress, "circle-wallet-address", "", "circle: the wallet's address, pinned (0x...)")
	fs.StringVar(&f.circleAPIKey, "circle-api-key-file", "", "circle: file holding the API key (owner-only)")
	fs.StringVar(&f.circleSecret, "circle-entity-secret-file", "", "circle: file holding the entity secret, 64 hex characters (owner-only)")
	fs.StringVar(&f.circlePubKey, "circle-public-key-file", "", "circle: Circle's RSA public key, PEM, pinned (owner-only)")
}

func (f *m3Flags) on() bool { return f.identity != "" }

func (f *m3Flags) remote() bool { return f.signer == "circle" }

// validate checks the flags without reading any file.
func (f *m3Flags) validate(mode string) error {
	if !f.on() {
		for name, v := range map[string]string{"rail": f.rail, "signer": f.signer, "eip3009-domain-name": f.domainName,
			"eip3009-domain-version": f.domainVersion, "circle-wallet-id": f.circleWallet, "circle-wallet-address": f.circleAddress,
			"circle-api-key-file": f.circleAPIKey, "circle-entity-secret-file": f.circleSecret, "circle-public-key-file": f.circlePubKey} {
			if v != "" {
				return fmt.Errorf("%w: -%s is an M3 setting and needs -server-identity", arcpay.ErrViolation, name)
			}
		}
		if f.maxLife != 0 {
			return fmt.Errorf("%w: -max-auth-lifetime is an M3 setting and needs -server-identity", arcpay.ErrViolation)
		}
		return nil
	}
	if err := checkServerIdentity(f.identity); err != nil {
		return fmt.Errorf("%w: %v", arcpay.ErrViolation, err)
	}
	switch f.rail {
	case railTransfer, railEIP3009:
	default:
		return fmt.Errorf("%w: -rail must be transfer or eip3009", arcpay.ErrViolation)
	}
	switch {
	case mode == modeEvaluate && f.signer != "":
		return fmt.Errorf("%w: evaluate-only holds no signer; remove -signer", arcpay.ErrViolation)
	case mode != modeEvaluate && f.signer != "key" && f.signer != "circle":
		return fmt.Errorf("%w: -signer must be key or circle", arcpay.ErrViolation)
	}
	if f.rail == railEIP3009 {
		if f.maxLife < minAuthLifetime {
			return fmt.Errorf("%w: -max-auth-lifetime %s is below this gateway's operational minimum of %s "+
				"(our margin over the facilitator's need for validBefore to be at least 6 s ahead when it verifies)",
				arcpay.ErrViolation, f.maxLife, minAuthLifetime)
		}
		if f.domainName == "" || f.domainVersion == "" {
			return fmt.Errorf("%w: -rail eip3009 needs the pinned -eip3009-domain-name and -eip3009-domain-version", arcpay.ErrViolation)
		}
	} else if f.maxLife != 0 || f.domainName != "" || f.domainVersion != "" {
		return fmt.Errorf("%w: EIP-3009 settings given for -rail transfer", arcpay.ErrViolation)
	}
	circleSet := f.circleWallet != "" || f.circleAddress != "" || f.circleAPIKey != "" || f.circleSecret != "" || f.circlePubKey != ""
	if f.remote() {
		if f.circleWallet == "" || f.circleAddress == "" || f.circleAPIKey == "" || f.circleSecret == "" || f.circlePubKey == "" {
			return fmt.Errorf("%w: -signer circle needs -circle-wallet-id, -circle-wallet-address and the three -circle-*-file flags", arcpay.ErrViolation)
		}
		if !common.IsHexAddress(f.circleAddress) || !strings.HasPrefix(f.circleAddress, "0x") {
			return fmt.Errorf("%w: -circle-wallet-address is not a 0x address", arcpay.ErrViolation)
		}
	} else if circleSet {
		return fmt.Errorf("%w: Circle settings given without -signer circle", arcpay.ErrViolation)
	}
	return nil
}

// resolveModeM3 is resolveMode for a gateway whose signer may be remote: a
// Circle signer takes the place of -key, and the two are never combined.
func resolveModeM3(evaluateOnly, dryRun bool, keyPath string, extra []string, remote bool) (string, error) {
	if !remote {
		return resolveMode(evaluateOnly, dryRun, keyPath, extra)
	}
	switch {
	case len(extra) > 0:
		return "", fmt.Errorf("%w: unexpected argument %q; every flag after it would be ignored", arcpay.ErrViolation, extra[0])
	case keyPath != "":
		return "", fmt.Errorf("%w: -signer circle and -key are two signers; choose one", arcpay.ErrViolation)
	case evaluateOnly:
		return "", fmt.Errorf("%w: evaluate-only holds no signer; remove -signer", arcpay.ErrViolation)
	case dryRun:
		return modeDryRun, nil
	}
	return modeLive, nil
}

// readSecretFile reads a one-line secret from a file that passes the key-file
// checks (owner-only, safe directory walk). The value is never printed.
func readSecretFile(path string) (string, error) {
	resolved, err := arcpay.ResolveKeyFile(path)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %v", arcpay.ErrUnavailable, resolved, err)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("%w: %s must hold exactly one line", arcpay.ErrViolation, resolved)
	}
	return s, nil
}

// loadCircle builds the Circle wallet from its flags.
func (f *m3Flags) loadCircle() (*circlewallet.Wallet, error) {
	apiKey, err := readSecretFile(f.circleAPIKey)
	if err != nil {
		return nil, err
	}
	secretHex, err := readSecretFile(f.circleSecret)
	if err != nil {
		return nil, err
	}
	var secret [32]byte
	if n, err := hex.Decode(secret[:], []byte(secretHex)); err != nil || n != 32 || len(secretHex) != 64 {
		return nil, fmt.Errorf("%w: the entity secret file must hold 64 hex characters", arcpay.ErrViolation)
	}
	resolved, err := arcpay.ResolveKeyFile(f.circlePubKey)
	if err != nil {
		return nil, err
	}
	pemBytes, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", arcpay.ErrUnavailable, resolved, err)
	}
	pub, err := parseRSAPublicKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", arcpay.ErrViolation, resolved, err)
	}
	return circlewallet.New(circlewallet.Config{BaseURL: f.circleBaseURL, APIKey: apiKey, EntitySecret: secret,
		CirclePublicKey: pub, WalletID: f.circleWallet, Address: common.HexToAddress(f.circleAddress)})
}

// parseRSAPublicKey accepts exactly one PEM block holding an RSA public key
// (PKIX "PUBLIC KEY" or PKCS#1 "RSA PUBLIC KEY") and nothing after it.
func parseRSAPublicKey(b []byte) (*rsa.PublicKey, error) {
	blk, rest := pem.Decode(b)
	if blk == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("want exactly one PEM block")
	}
	switch blk.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		return rk, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(blk.Bytes)
	}
	return nil, fmt.Errorf("PEM block type %q is not a public key", blk.Type)
}

// buildM3 opens the correlation file next to the log, verifies it against the
// log, and assembles the M3 server settings. payKey or wallet is the signer
// (both nil in evaluate-only mode).
func (f *m3Flags) buildM3(mode, logPath string, log *translog.Log, logKey ed25519.PrivateKey, cp capability,
	payKey *ecdsa.PrivateKey, wallet *circlewallet.Wallet) (*m3, error) {
	net := cp.Net
	// The EIP-3009 rail compares the resource server's resource.url with the
	// human-approved one; without it the rail cannot validate requirements.
	if f.rail == railEIP3009 && cp.ResourceURL == "" {
		return nil, fmt.Errorf("%w: -rail eip3009 needs resource_url in the capability file", arcpay.ErrViolation)
	}
	corr, err := correlation.Open(logPath+".correlation", logKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	logHash := func(seq uint64) ([32]byte, bool) {
		if seq > uint64(log.Len()) {
			return [32]byte{}, false
		}
		r, ok := log.At(int(seq))
		if !ok {
			return [32]byte{}, false
		}
		return r.Hash(), true
	}
	if err := correlation.CheckAgainstLog(corr.Records(), logHash); err != nil {
		corr.Close()
		return nil, err
	}
	m := &m3{identity: f.identity, corr: corr, logKey: logKey, logHash: logHash, rail: f.rail, txRail: correlation.RailLocalKeyTx}
	if wallet != nil {
		m.txRail = correlation.RailCircleWalletsTx
	}
	if f.rail == railEIP3009 {
		m.domain = eip3009.Domain{Name: f.domainName, Version: f.domainVersion, ChainID: net.ChainID, VerifyingContract: net.USDC}
		m.maxLife = f.maxLife
		m.x402 = x402v2.Config{Network: net.CAIP2, ResourceURL: cp.ResourceURL, MaxTimeoutCeiling: maxTimeoutCeiling}
		switch {
		case payKey != nil:
			m.payer = evm.Address(crypto.PubkeyToAddress(payKey.PublicKey))
			m.signEIP = func(_ context.Context, b eip3009.Bound) ([]byte, error) { return eip3009sign.Sign(b, payKey) }
		case wallet != nil:
			m.payer = evm.Address(wallet.Address())
			m.signEIP = func(ctx context.Context, b eip3009.Bound) ([]byte, error) {
				doc, err := b.TypedDataJSON()
				if err != nil {
					return nil, err
				}
				sig, err := wallet.SignTypedData(ctx, doc)
				if err != nil {
					return nil, err
				}
				return sig, eip3009sign.Check(b, sig)
			}
		}
		if mode == modeDryRun {
			m.signEIP = nil
		}
	}
	return m, nil
}

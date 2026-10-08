//go:build arc

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/correlation"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

func goodEIP() m3Flags {
	return m3Flags{identity: identity, rail: railEIP3009, signer: "key", maxLife: 2 * time.Minute, domainName: "USDC", domainVersion: "2"}
}

func goodCircle() m3Flags {
	return m3Flags{identity: identity, rail: railTransfer, signer: "circle", circleWallet: "w-1",
		circleAddress: "0x79A34Cc563f848f626038Ff312CCEBfb5374971d", circleAPIKey: "/k/api", circleSecret: "/k/secret", circlePubKey: "/k/pub.pem"}
}

func TestM3FlagValidation(t *testing.T) {
	ok := []struct {
		name string
		f    m3Flags
		mode string
	}{
		{"M2 gateway, no M3 flags", m3Flags{}, modeLive},
		{"eip3009 with a key", goodEIP(), modeLive},
		{"transfer with Circle", goodCircle(), modeLive},
		{"evaluate-only, no signer", m3Flags{identity: identity, rail: railTransfer}, modeEvaluate},
	}
	for _, c := range ok {
		if err := c.f.validate(c.mode); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
	}
	bad := map[string]struct {
		f    func() m3Flags
		mode string
	}{
		"rail without identity":          {func() m3Flags { return m3Flags{rail: railTransfer} }, modeLive},
		"lifetime without identity":      {func() m3Flags { return m3Flags{maxLife: time.Minute} }, modeLive},
		"circle id without identity":     {func() m3Flags { return m3Flags{circleWallet: "w"} }, modeLive},
		"identity with trailing space":   {func() m3Flags { f := goodEIP(); f.identity += " "; return f }, modeLive},
		"unknown rail":                   {func() m3Flags { f := goodEIP(); f.rail = "permit2"; return f }, modeLive},
		"no rail":                        {func() m3Flags { f := goodEIP(); f.rail = ""; return f }, modeLive},
		"no signer in live mode":         {func() m3Flags { f := goodEIP(); f.signer = ""; return f }, modeLive},
		"unknown signer":                 {func() m3Flags { f := goodEIP(); f.signer = "hsm"; return f }, modeLive},
		"signer in evaluate-only":        {func() m3Flags { return goodEIP() }, modeEvaluate},
		"eip3009 without lifetime":       {func() m3Flags { f := goodEIP(); f.maxLife = 0; return f }, modeLive},
		"eip3009 with negative lifetime": {func() m3Flags { f := goodEIP(); f.maxLife = -time.Second; return f }, modeLive},
		"eip3009 without domain name":    {func() m3Flags { f := goodEIP(); f.domainName = ""; return f }, modeLive},
		"eip3009 without domain version": {func() m3Flags { f := goodEIP(); f.domainVersion = ""; return f }, modeLive},
		"eip3009 settings on transfer":   {func() m3Flags { f := goodCircle(); f.maxLife = time.Minute; return f }, modeLive},
		"circle without wallet id":       {func() m3Flags { f := goodCircle(); f.circleWallet = ""; return f }, modeLive},
		"circle without secret file":     {func() m3Flags { f := goodCircle(); f.circleSecret = ""; return f }, modeLive},
		"circle address malformed": {func() m3Flags {
			f := goodCircle()
			f.circleAddress = "79A34Cc563f848f626038Ff312CCEBfb5374971d"
			return f
		}, modeLive},
		"circle settings with key signer": {func() m3Flags { f := goodEIP(); f.circleWallet = "w"; return f }, modeLive},
	}
	for name, c := range bad {
		f := c.f()
		if err := f.validate(c.mode); !errors.Is(err, arcpay.ErrViolation) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestResolveModeM3(t *testing.T) {
	if m, err := resolveModeM3(false, false, "", nil, true); err != nil || m != modeLive {
		t.Fatalf("circle live: %q %v", m, err)
	}
	if m, err := resolveModeM3(false, true, "", nil, true); err != nil || m != modeDryRun {
		t.Fatalf("circle dry run: %q %v", m, err)
	}
	for name, c := range map[string]struct {
		eval bool
		key  string
		args []string
	}{
		"circle and a key":     {false, "/k/pay", nil},
		"circle evaluate-only": {true, "", nil},
		"stray argument":       {false, "", []string{"x"}},
	} {
		if _, err := resolveModeM3(c.eval, false, c.key, c.args, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkix, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	good := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&k.PublicKey)})
	for _, b := range [][]byte{good, pkcs1, append(append([]byte(nil), good...), '\n')} {
		if got, err := parseRSAPublicKey(b); err != nil || got.N.Cmp(k.N) != 0 {
			t.Fatalf("refused a good key: %v", err)
		}
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKIXPublicKey(edPub)
	for name, b := range map[string][]byte{
		"two blocks":    append(append([]byte(nil), good...), good...),
		"not PEM":       []byte("not a key"),
		"private key":   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}),
		"Ed25519 key":   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER}),
		"trailing junk": append(append([]byte(nil), good...), []byte("junk")...),
	} {
		if _, err := parseRSAPublicKey(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadSecretFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if s, err := readSecretFile(write("ok", "secret-value\n", 0o600)); err != nil || s != "secret-value" {
		t.Fatalf("good secret: %q %v", s, err)
	}
	for name, p := range map[string]string{
		"group readable": write("g", "x\n", 0o640),
		"two lines":      write("two", "a\nb\n", 0o600),
		"empty":          write("e", "\n", 0o600),
		"missing":        filepath.Join(dir, "nope"),
	} {
		if _, err := readSecretFile(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// buildM3 opens the correlation file next to the log and refuses one that does
// not match the log.
func TestBuildM3VerifiesTheCorrelationFileAgainstTheLog(t *testing.T) {
	logKey := ed25519.NewKeyFromSeed(logSeed[:])
	log := translog.NewLog(logKey.Public().(ed25519.PublicKey))
	if _, err := log.Append(logKey, translog.Allow, [32]byte{1}, t0.Unix()); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "log.json")
	f := m3Flags{identity: identity, rail: railTransfer}
	m, err := f.buildM3(modeEvaluate, logPath, log, logKey, capability{Net: evm.ArcTestnet()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := m.logHash(0)
	if !ok {
		t.Fatal("log entry 0 not found")
	}
	if _, err := m.corr.Append(correlation.Record{LogSeq: 0, LogRecordHash: h, PaymentID: [32]byte{1}}, logKey); err != nil {
		t.Fatal(err)
	}
	m.corr.Close()
	if m, err := f.buildM3(modeEvaluate, logPath, log, logKey, capability{Net: evm.ArcTestnet()}, nil, nil); err != nil {
		t.Fatalf("a matching file was refused: %v", err)
	} else {
		m.corr.Close()
	}
	// The same correlation file against a different log is refused.
	other := translog.NewLog(logKey.Public().(ed25519.PublicKey))
	if _, err := other.Append(logKey, translog.Allow, [32]byte{2}, t0.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.buildM3(modeEvaluate, logPath, other, logKey, capability{Net: evm.ArcTestnet()}, nil, nil); !errors.Is(err, correlation.ErrCorrupt) {
		t.Fatalf("a correlation file for another log was accepted: %v", err)
	}
}

func TestToolsListAdvertisesTheM3Arguments(t *testing.T) {
	s := newTestServer(&fixedAuthorizer{}, nil, new(int))
	s.m3 = newM3(t, railTransfer)
	b, _ := json.Marshal(s.toolsList())
	for _, want := range []string{`"payment_id"`, `"server_identity"`, identity, `"additionalProperties":false`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("tools/list lacks %s: %s", want, b)
		}
	}
}

// The operational minimum for -max-auth-lifetime (30 s), at its boundary.
func TestMaxAuthLifetimeMinimum(t *testing.T) {
	if minAuthLifetime != 30*time.Second {
		t.Fatalf("minimum is %s; a change needs evidence and a spec update", minAuthLifetime)
	}
	for _, c := range []struct {
		d  time.Duration
		ok bool
	}{
		{0, false},
		{time.Nanosecond, false},
		{6 * time.Second, false}, // the facilitator's own figure is not our minimum
		{29 * time.Second, false},
		{30*time.Second - time.Nanosecond, false},
		{30 * time.Second, true},
		{30*time.Second + time.Nanosecond, true},
		{31 * time.Second, true},
		{2 * time.Minute, true},
		{-30 * time.Second, false},
	} {
		f := goodEIP()
		f.maxLife = c.d
		err := f.validate(modeLive)
		if c.ok && err != nil {
			t.Errorf("%s refused: %v", c.d, err)
		}
		if !c.ok && !errors.Is(err, arcpay.ErrViolation) {
			t.Errorf("%s accepted", c.d)
		}
	}
	// The message must not present 30 s as an x402 rule.
	f := goodEIP()
	f.maxLife = 29 * time.Second
	if err := f.validate(modeLive); err == nil || !strings.Contains(err.Error(), "operational minimum") || strings.Contains(err.Error(), "x402 requires") {
		t.Fatalf("message: %v", err)
	}
}

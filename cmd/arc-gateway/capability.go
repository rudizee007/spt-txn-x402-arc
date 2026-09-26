//go:build arc

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// capability is the one payment authority a human approved (SPEC-ARC-GATE §3).
// It is read once at startup; nothing the agent sends can change it.
type capability struct {
	Net         evm.ArcNetwork
	Recipient   evm.Address
	Resource    string
	MaxMicro    uint64
	MaxPayments int
	ExpiresAt   time.Time
}

// capabilityFile is the on-disk form. Every field is required except
// max_payments, which defaults to 1.
type capabilityFile struct {
	Network        string  `json:"network"`
	Recipient      string  `json:"recipient"`
	Resource       string  `json:"resource"`
	MaxAmountMicro *uint64 `json:"max_amount_micro"`
	MaxPayments    *int    `json:"max_payments"`
	ExpiresAt      string  `json:"expires_at"`
}

var errCapability = errors.New("capability refused")

// parseCapability reads a capability strictly: unknown fields, trailing data,
// a missing field, a zero ceiling, an unparseable or past expiry, and a
// network name other than exactly "testnet" or "mainnet" are all refused.
func parseCapability(r io.Reader, now time.Time) (capability, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil {
		return capability{}, fmt.Errorf("%w: read: %v", errCapability, err)
	}
	if err := exactKeys(raw); err != nil {
		return capability{}, fmt.Errorf("%w: %v", errCapability, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f capabilityFile
	if err := dec.Decode(&f); err != nil {
		return capability{}, fmt.Errorf("%w: %v", errCapability, err)
	}
	if dec.More() {
		return capability{}, fmt.Errorf("%w: trailing data after the capability object", errCapability)
	}
	net, err := evm.ArcNetworkByName(f.Network)
	if err != nil {
		return capability{}, fmt.Errorf("%w: %v", errCapability, err)
	}
	rcpt, err := evm.ParseAddress(f.Recipient)
	if err != nil {
		return capability{}, fmt.Errorf("%w: recipient: %v", errCapability, err)
	}
	if rcpt.IsZero() {
		return capability{}, fmt.Errorf("%w: recipient is the zero address", errCapability)
	}
	if f.Resource == "" {
		return capability{}, fmt.Errorf("%w: resource is required", errCapability)
	}
	if f.MaxAmountMicro == nil || *f.MaxAmountMicro == 0 {
		return capability{}, fmt.Errorf("%w: max_amount_micro is required and must be positive", errCapability)
	}
	maxPayments := 1
	if f.MaxPayments != nil {
		if *f.MaxPayments < 1 {
			return capability{}, fmt.Errorf("%w: max_payments must be at least 1", errCapability)
		}
		maxPayments = *f.MaxPayments
	}
	if f.ExpiresAt == "" {
		return capability{}, fmt.Errorf("%w: expires_at is required", errCapability)
	}
	exp, err := time.Parse(time.RFC3339, f.ExpiresAt)
	if err != nil {
		return capability{}, fmt.Errorf("%w: expires_at: %v", errCapability, err)
	}
	if !exp.After(now) {
		return capability{}, fmt.Errorf("%w: expired at %s", errCapability, exp.Format(time.RFC3339))
	}
	return capability{
		Net: net, Recipient: rcpt, Resource: f.Resource,
		MaxMicro: *f.MaxAmountMicro, MaxPayments: maxPayments, ExpiresAt: exp,
	}, nil
}

// loadCapability reads and parses a capability file, and returns the SHA-256
// of its exact bytes, which keys the persisted payment count.
func loadCapability(path string, now time.Time) (capability, [32]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return capability{}, [32]byte{}, fmt.Errorf("%w: %v", errCapability, err)
	}
	c, err := parseCapability(bytes.NewReader(raw), now)
	return c, sha256.Sum256(raw), err
}

// countState is the persisted number of ALLOWs issued under one capability
// (SPEC-ARC-GATE §3). It survives a restart, so ending the process, whoever
// ends it, does not reset max_payments.
type countState struct {
	CapabilitySHA256 string `json:"capability_sha256"`
	Allows           int    `json:"allows"`
}

// loadCount returns the count recorded for this capability, or 0 if the file
// is absent or records a different capability. A malformed file is refused.
func loadCount(path string, digest [32]byte) (int, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var st countState
	if err := json.Unmarshal(raw, &st); err != nil || st.Allows < 0 {
		return 0, fmt.Errorf("payment count file %s is malformed", path)
	}
	if st.CapabilitySHA256 != hex.EncodeToString(digest[:]) {
		return 0, nil
	}
	return st.Allows, nil
}

// saveCount writes the count atomically: temp file, fsync, rename.
func saveCount(path string, digest [32]byte, allows int) error {
	b, err := json.Marshal(countState{CapabilitySHA256: hex.EncodeToString(digest[:]), Allows: allows})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".arc-gateway-count-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// capabilityKeys are the only keys a capability file may contain, spelled
// exactly. encoding/json matches field names case-insensitively and lets a later
// duplicate win, so {"recipient": A, "Recipient": B} decodes to B while a person
// reading the file sees A. exactKeys refuses both before the file is decoded.
var capabilityKeys = map[string]bool{
	"network": true, "recipient": true, "resource": true,
	"max_amount_micro": true, "max_payments": true, "expires_at": true,
}

func exactKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("a capability must be a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("malformed capability object")
		}
		if !capabilityKeys[key] {
			return fmt.Errorf("unknown or wrongly spelled key %q", key)
		}
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

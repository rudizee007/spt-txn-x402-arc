//go:build arc

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

func loadCapability(path string, now time.Time) (capability, error) {
	f, err := os.Open(path)
	if err != nil {
		return capability{}, fmt.Errorf("%w: %v", errCapability, err)
	}
	defer f.Close()
	return parseCapability(f, now)
}

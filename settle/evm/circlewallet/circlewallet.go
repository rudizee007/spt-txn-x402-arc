//go:build arc

// Package circlewallet signs through a Circle developer-controlled wallet,
// without broadcasting, for the guarded paths in arcpay (raw transactions) and
// settle/eip3009 (typed data) (SPEC-ARC-M3 §4.2).
//
// Nothing a response carries is trusted. The raw-transaction path is
// re-checked by arcpay, which decodes, recovers the sender, compares every
// field and broadcasts itself. The typed-data path is re-checked by
// eip3009sign, which recovers the signer over the guard's own digest.
//
// Pinned, never fetched: the wallet's address, and Circle's RSA public key used
// to encrypt the entity secret. A key fetched at run time could be supplied by
// whoever answers the request.
//
// NOT YET VERIFIED against Circle's API reference (SPEC-ARC-M3 V-3, V-4):
//   - the endpoint paths;
//   - the request and response member names;
//   - RSA-OAEP with SHA-256 for the entity-secret ciphertext;
//   - which wallet types may sign raw transactions on ARC.
//
// They are named constants so the week-one check changes one place.
package circlewallet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// API surface (V-3: to be confirmed).
const (
	DefaultBaseURL    = "https://api.circle.com"
	PathSignTx        = "/v1/w3s/developer/sign/transaction"
	PathSignTypedData = "/v1/w3s/developer/sign/typedData"
	maxResponse       = 1 << 20
)

// Errors. A failure to reach or be understood by the provider is unavailable;
// an answer of the wrong shape is a violation.
var (
	ErrConfig      = errors.New("circlewallet: configuration")
	ErrUnavailable = errors.New("circlewallet: provider unavailable")
	ErrResponse    = errors.New("circlewallet: provider response is malformed")
)

// Config is one developer-controlled wallet.
type Config struct {
	BaseURL         string // https only; DefaultBaseURL if empty
	APIKey          string
	EntitySecret    [32]byte
	CirclePublicKey *rsa.PublicKey // pinned
	WalletID        string
	Address         common.Address // pinned: the account the wallet signs for
	HTTP            *http.Client   // http.DefaultClient if nil
}

// Wallet implements arcpay.RemoteSigner.
type Wallet struct {
	cfg  Config
	base *url.URL
}

// New validates cfg. It refuses a non-https base URL, an empty API key, wallet
// id or address, an all-zero entity secret and a missing or short RSA key.
func New(cfg Config) (*Wallet, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "":
		return nil, fmt.Errorf("%w: base URL must be https://host", ErrConfig)
	case cfg.APIKey == "" || strings.ContainsAny(cfg.APIKey, " \r\n\t"):
		return nil, fmt.Errorf("%w: API key is empty or malformed", ErrConfig)
	case cfg.WalletID == "" || strings.ContainsAny(cfg.WalletID, " \r\n\t/"):
		return nil, fmt.Errorf("%w: wallet id is empty or malformed", ErrConfig)
	case cfg.Address == (common.Address{}):
		return nil, fmt.Errorf("%w: wallet address must be pinned", ErrConfig)
	case cfg.EntitySecret == [32]byte{}:
		return nil, fmt.Errorf("%w: entity secret is unset", ErrConfig)
	case cfg.CirclePublicKey == nil || cfg.CirclePublicKey.N.BitLen() < 2048:
		return nil, fmt.Errorf("%w: Circle's public key must be pinned (RSA, at least 2048 bits)", ErrConfig)
	}
	u.Path = ""
	if cfg.HTTP == nil {
		cfg.HTTP = http.DefaultClient
	}
	return &Wallet{cfg: cfg, base: u}, nil
}

// Address is the pinned account.
func (w *Wallet) Address() common.Address { return w.cfg.Address }

// ciphertext encrypts the entity secret afresh for one request (V-3: RSA-OAEP,
// SHA-256). Each request gets a new ciphertext; Circle refuses a reused one.
func (w *Wallet) ciphertext() (string, error) {
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, w.cfg.CirclePublicKey, w.cfg.EntitySecret[:], nil)
	if err != nil {
		return "", fmt.Errorf("%w: encrypt entity secret: %v", ErrConfig, err)
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// post sends one request and decodes data into out. The API key and the
// ciphertext never appear in an error.
func (w *Wallet) post(ctx context.Context, path string, body map[string]string, out interface{}) error {
	ct, err := w.ciphertext()
	if err != nil {
		return err
	}
	body["walletId"] = w.cfg.WalletID
	body["entitySecretCiphertext"] = ct
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := *w.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := w.cfg.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, redact(err.Error(), w.cfg.APIKey))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("%w: read: %v", ErrUnavailable, err)
	}
	if len(raw) > maxResponse {
		return fmt.Errorf("%w: response larger than %d bytes", ErrResponse, maxResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Data) == 0 || env.Data[0] != '{' {
		return fmt.Errorf("%w: no data object", ErrResponse)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("%w: data: %v", ErrResponse, err)
	}
	return nil
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}

// SignTransaction asks the wallet to sign an unsigned EIP-1559 transaction
// without broadcasting it, and returns the signed transaction and the hash the
// provider reports, or nil if it reports none (txHash is optional in Circle's
// published SDK types; V-3 remains open). arcpay re-checks both.
func (w *Wallet) SignTransaction(ctx context.Context, unsigned []byte) ([]byte, *common.Hash, error) {
	var data struct {
		Signature         string  `json:"signature"`
		SignedTransaction string  `json:"signedTransaction"`
		TxHash            *string `json:"txHash"` // absent and null are both "not reported"
	}
	if err := w.post(ctx, PathSignTx, map[string]string{"rawTransaction": "0x" + hex.EncodeToString(unsigned)}, &data); err != nil {
		return nil, nil, err
	}
	signed, err := hex0x(data.SignedTransaction, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signedTransaction: %v", ErrResponse, err)
	}
	if data.TxHash == nil {
		return signed, nil, nil
	}
	h, err := hex0x(*data.TxHash, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: txHash: %v", ErrResponse, err)
	}
	reported := common.BytesToHash(h)
	return signed, &reported, nil
}

// SignTypedData asks the wallet to sign EIP-712 typed data (the C4 fallback)
// and returns the 65-byte signature. eip3009sign.Check judges it against the
// guard's own digest.
func (w *Wallet) SignTypedData(ctx context.Context, typedDataJSON []byte) ([]byte, error) {
	var data struct {
		Signature string `json:"signature"`
	}
	if err := w.post(ctx, PathSignTypedData, map[string]string{"data": string(typedDataJSON)}, &data); err != nil {
		return nil, err
	}
	sig, err := hex0x(data.Signature, 65)
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrResponse, err)
	}
	return sig, nil
}

// hex0x decodes 0x-prefixed hex, requiring exactly n bytes if n > 0 and at
// least one byte otherwise.
func hex0x(s string, n int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, errors.New("not 0x-prefixed hex")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, err
	}
	if (n > 0 && len(b) != n) || len(b) == 0 {
		return nil, fmt.Errorf("%d bytes", len(b))
	}
	return b, nil
}

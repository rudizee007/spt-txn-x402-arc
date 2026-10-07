//go:build arc

package circlewallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009/eip3009sign"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay/arcpaytest"
)

const apiKey = "TEST_API_KEY:0123456789abcdef"

var entitySecret = [32]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}

// fakeCircle plays the developer-controlled wallet API over TLS. It decrypts
// the entity secret with its own RSA key and signs with the wallet key, never
// broadcasting. Its hooks turn it hostile.
type fakeCircle struct {
	t      *testing.T
	rsa    *rsa.PrivateKey
	wallet *ecdsa.PrivateKey
	srv    *httptest.Server

	mu          sync.Mutex
	ciphertexts []string
	bodies      []map[string]string
	status      int
	rawReply    string
	alterTx     func(*types.DynamicFeeTx)
	alterTyped  func(map[string]interface{})
	txHashMode  string // "" correct, "omit", "null", "wrong"
}

func newFake(t *testing.T) *fakeCircle {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wk, _ := crypto.GenerateKey()
	f := &fakeCircle{t: t, rsa: rk, wallet: wk, status: 200}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCircle) wallet0(t *testing.T) *Wallet {
	t.Helper()
	w, err := New(Config{BaseURL: f.srv.URL, APIKey: apiKey, EntitySecret: entitySecret, CirclePublicKey: &f.rsa.PublicKey,
		WalletID: "wallet-1", Address: crypto.PubkeyToAddress(f.wallet.PublicKey), HTTP: f.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (f *fakeCircle) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `{"code":1,"message":"`+msg+`"}`)
	}
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+apiKey || r.Header.Get("Content-Type") != "application/json" {
		fail(401, "bad request headers")
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(400, "body")
		return
	}
	f.bodies = append(f.bodies, body)
	ct, err := base64.StdEncoding.DecodeString(body["entitySecretCiphertext"])
	if err != nil {
		fail(400, "ciphertext encoding")
		return
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), nil, f.rsa, ct, nil)
	if err != nil || !bytesEq(secret, entitySecret[:]) {
		fail(401, "entity secret")
		return
	}
	f.ciphertexts = append(f.ciphertexts, body["entitySecretCiphertext"])
	if body["walletId"] != "wallet-1" {
		fail(404, "wallet")
		return
	}
	if f.status != 200 {
		fail(f.status, "configured failure")
		return
	}
	if f.rawReply != "" {
		_, _ = io.WriteString(w, f.rawReply)
		return
	}
	switch r.URL.Path {
	case PathSignTx:
		raw, err := hex.DecodeString(strings.TrimPrefix(body["rawTransaction"], "0x"))
		if err != nil || len(raw) < 2 || raw[0] != 2 {
			fail(400, "rawTransaction")
			return
		}
		var fl struct {
			ChainID    *big.Int
			Nonce      uint64
			Tip, Fee   *big.Int
			Gas        uint64
			To         *common.Address
			Value      *big.Int
			Data       []byte
			AccessList types.AccessList
		}
		if err := rlp.DecodeBytes(raw[1:], &fl); err != nil {
			fail(400, "rlp")
			return
		}
		inner := &types.DynamicFeeTx{ChainID: fl.ChainID, Nonce: fl.Nonce, GasTipCap: fl.Tip, GasFeeCap: fl.Fee, Gas: fl.Gas, To: fl.To, Value: fl.Value, Data: fl.Data, AccessList: fl.AccessList}
		if f.alterTx != nil {
			f.alterTx(inner)
		}
		signed, err := types.SignNewTx(f.wallet, types.LatestSignerForChainID(inner.ChainID), inner)
		if err != nil {
			fail(500, "sign")
			return
		}
		enc, _ := signed.MarshalBinary()
		data := map[string]interface{}{"signature": "0x00", "signedTransaction": "0x" + hex.EncodeToString(enc)}
		switch f.txHashMode {
		case "":
			data["txHash"] = signed.Hash().Hex()
		case "null":
			data["txHash"] = nil
		case "wrong":
			h := signed.Hash()
			h[31] ^= 1
			data["txHash"] = h.Hex()
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	case PathSignTypedData:
		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(body["data"]), &doc); err != nil {
			fail(400, "data")
			return
		}
		if f.alterTyped != nil {
			f.alterTyped(doc)
		}
		b, _ := json.Marshal(doc)
		var td apitypes.TypedData
		if err := json.Unmarshal(b, &td); err != nil {
			fail(400, "typed data")
			return
		}
		h, _, err := apitypes.TypedDataAndHash(td)
		if err != nil {
			fail(400, "hash: "+err.Error())
			return
		}
		sig, _ := crypto.Sign(h, f.wallet)
		sig[64] += 27
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"signature": "0x" + hex.EncodeToString(sig)}})
	default:
		fail(404, "path")
	}
}

func bytesEq(a, b []byte) bool { return string(a) == string(b) }

func TestNewRefusesUnsafeConfiguration(t *testing.T) {
	f := newFake(t)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	good := Config{BaseURL: f.srv.URL, APIKey: apiKey, EntitySecret: entitySecret, CirclePublicKey: &f.rsa.PublicKey, WalletID: "w", Address: common.Address{1}}
	for name, mod := range map[string]func(*Config){
		"http base URL":        func(c *Config) { c.BaseURL = "http://api.circle.com" },
		"base URL with path":   func(c *Config) { c.BaseURL = "https://api.circle.com/v1" },
		"base URL with user":   func(c *Config) { c.BaseURL = "https://u:p@api.circle.com" },
		"empty API key":        func(c *Config) { c.APIKey = "" },
		"API key with newline": func(c *Config) { c.APIKey = "a\nb" },
		"empty wallet id":      func(c *Config) { c.WalletID = "" },
		"wallet id with slash": func(c *Config) { c.WalletID = "a/b" },
		"unpinned address":     func(c *Config) { c.Address = common.Address{} },
		"zero entity secret":   func(c *Config) { c.EntitySecret = [32]byte{} },
		"no Circle public key": func(c *Config) { c.CirclePublicKey = nil },
		"1024-bit Circle key":  func(c *Config) { c.CirclePublicKey = &small.PublicKey },
	} {
		c := good
		mod(&c)
		if _, err := New(c); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(good); err != nil {
		t.Fatalf("good configuration refused: %v", err)
	}
}

func TestEachRequestCarriesAFreshCiphertextAndNoSecretLeaks(t *testing.T) {
	f := newFake(t)
	w := f.wallet0(t)
	f.status = 503
	_, _, err1 := w.SignTransaction(context.Background(), []byte{2, 0xc0})
	_, _, err2 := w.SignTransaction(context.Background(), []byte{2, 0xc0})
	if !errors.Is(err1, ErrUnavailable) || !errors.Is(err2, ErrUnavailable) {
		t.Fatalf("503 not reported as unavailable: %v / %v", err1, err2)
	}
	if len(f.ciphertexts) != 2 || f.ciphertexts[0] == f.ciphertexts[1] {
		t.Fatal("the entity-secret ciphertext was reused across requests")
	}
	for _, e := range []error{err1, err2} {
		if strings.Contains(e.Error(), apiKey) || strings.Contains(e.Error(), f.ciphertexts[0]) {
			t.Fatal("an error message carries a secret")
		}
	}
}

func TestMalformedResponsesAreRefused(t *testing.T) {
	for name, reply := range map[string]string{
		"not JSON":           `<html>oops</html>`,
		"no data":            `{"result":{}}`,
		"data not an object": `{"data":"0x02"}`,
		"no 0x prefix":       `{"data":{"signedTransaction":"02f8","txHash":"0x` + strings.Repeat("ab", 32) + `"}}`,
		"bad hex":            `{"data":{"signedTransaction":"0xzz","txHash":"0x` + strings.Repeat("ab", 32) + `"}}`,
		"short hash":         `{"data":{"signedTransaction":"0x02c0","txHash":"0xabcd"}}`,
		"empty transaction":  `{"data":{"signedTransaction":"0x","txHash":"0x` + strings.Repeat("ab", 32) + `"}}`,
		"oversize":           `{"data":{"signedTransaction":"0x` + strings.Repeat("00", maxResponse) + `"}}`,
	} {
		f := newFake(t)
		f.rawReply = reply
		if _, _, err := f.wallet0(t).SignTransaction(context.Background(), []byte{2, 0xc0}); !errors.Is(err, ErrResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// End to end through arcpay: the Circle wallet signs, the guard re-checks, and
// this process broadcasts. A hostile wallet's re-addressed transaction is
// refused with nothing broadcast (C1, C2).
func TestSettleThroughCircleWallet(t *testing.T) {
	for _, hostile := range []bool{false, true} {
		f := newFake(t)
		w := f.wallet0(t)
		if hostile {
			f.alterTx = func(tx *types.DynamicFeeTx) { tx.Value = big.NewInt(1) }
		}
		net := evm.ArcTestnet()
		chain := arcpaytest.New(net.ChainID)
		t.Cleanup(chain.Close)
		c, err := ethclient.Dial(chain.URL())
		if err != nil {
			t.Fatal(err)
		}
		rcpt := evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d")
		_, err = arcpay.Settle(context.Background(), arcpay.Config{Net: net, Client: c, Remote: w, MaxFeeMicro: 50_000, ConfirmTimeout: 5 * time.Second},
			arcpay.Payment{Authorization: "1:ab", Recipient: rcpt, PayToTransport: evm.AccountIDBase58(rcpt), AssetTransport: evm.AccountIDBase58(net.USDC),
				AmountMicro: "500000", NotAfter: time.Now().Add(time.Hour)})
		switch {
		case !hostile && (err != nil || len(chain.Broadcasts()) != 1):
			t.Fatalf("honest wallet: %v, %d broadcasts", err, len(chain.Broadcasts()))
		case hostile && (!errors.Is(err, arcpay.ErrViolation) || len(chain.Broadcasts()) != 0):
			t.Fatalf("hostile wallet: %v, %d broadcasts", err, len(chain.Broadcasts()))
		}
	}
}

// The C4 fallback: the wallet signs EIP-3009 typed data. Its signature is
// accepted only if it recovers to the payer over the guard's own digest; a
// wallet that signs an altered document is refused.
func TestTypedDataFallback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(map[string]interface{})
		ok    bool
	}{
		{"honest", nil, true},
		{"recipient altered", func(d map[string]interface{}) {
			d["message"].(map[string]interface{})["to"] = "0x00000000000000000000000000000000000000aa"
		}, false},
		{"value altered", func(d map[string]interface{}) { d["message"].(map[string]interface{})["value"] = "500001" }, false},
		{"validBefore extended", func(d map[string]interface{}) { d["message"].(map[string]interface{})["validBefore"] = "99999999999" }, false},
		{"chain altered", func(d map[string]interface{}) { d["domain"].(map[string]interface{})["chainId"] = json.Number("5042") }, false},
	} {
		f := newFake(t)
		f.alterTyped = tc.alter
		w := f.wallet0(t)
		now := time.Now()
		b, err := eip3009.Bind(eip3009.Binding{
			Domain: eip3009.Domain{Name: "USDC", Version: "2", ChainID: evm.ArcTestnetChainID, VerifyingContract: evm.ArcTestnet().USDC},
			From:   evm.Address(w.Address()), To: evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d"), Value: big.NewInt(500_000),
			Intent: intent.Digest{1}, CapabilityExpiry: now.Add(time.Hour), CallExpiry: now.Add(time.Minute), MaxLifetime: 5 * time.Minute,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := b.TypedDataJSON()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := w.SignTypedData(context.Background(), doc)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		err = eip3009sign.Check(b, sig)
		if tc.ok && err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, eip3009.ErrViolation) {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// txHash is optional in Circle's published SDK types (V-3 open). Absent or null:
// accepted, the locally computed hash is authoritative. Present: must match.
func TestProviderTxHashOptionalButBinding(t *testing.T) {
	for _, c := range []struct {
		mode string
		ok   bool
	}{{"omit", true}, {"null", true}, {"", true}, {"wrong", false}} {
		f := newFake(t)
		f.txHashMode = c.mode
		w := f.wallet0(t)
		net := evm.ArcTestnet()
		chain := arcpaytest.New(net.ChainID)
		t.Cleanup(chain.Close)
		cl, err := ethclient.Dial(chain.URL())
		if err != nil {
			t.Fatal(err)
		}
		rcpt := evm.MustParseAddress("0x79A34Cc563f848f626038Ff312CCEBfb5374971d")
		res, err := arcpay.Settle(context.Background(), arcpay.Config{Net: net, Client: cl, Remote: w, MaxFeeMicro: 50_000, ConfirmTimeout: 5 * time.Second},
			arcpay.Payment{Authorization: "1:ab", Recipient: rcpt, PayToTransport: evm.AccountIDBase58(rcpt), AssetTransport: evm.AccountIDBase58(net.USDC),
				AmountMicro: "500000", NotAfter: time.Now().Add(time.Hour)})
		if c.ok {
			if err != nil || len(chain.Broadcasts()) != 1 || res.TxHash != chain.Broadcasts()[0].Hash() {
				t.Errorf("txHash %q: err=%v broadcasts=%d", c.mode, err, len(chain.Broadcasts()))
			}
		} else if !errors.Is(err, arcpay.ErrRemoteHash) || len(chain.Broadcasts()) != 0 {
			t.Errorf("wrong txHash: err=%v broadcasts=%d", err, len(chain.Broadcasts()))
		}
	}
}

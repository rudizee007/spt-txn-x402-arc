//go:build arc

// Package arcpaytest is a fake Arc JSON-RPC endpoint for tests. It answers the
// calls arcpay and cmd/arc-gateway make, each answer adjustable so a test can
// play an honest node or a hostile one, and it records every raw transaction
// it is asked to broadcast. It holds no keys and signs nothing.
package arcpaytest

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// Fake is a scriptable Arc node. Zero values are honest defaults set by New.
type Fake struct {
	mu sync.Mutex

	ChainID        uint64
	BalanceMicro   uint64   // ERC-20 view; the native view is this x 10^12 plus NativeDust
	NativeDust     *big.Int // added to the native balance
	NativeOverride *big.Int // if set, the native balance, ignoring the above
	Nonce          uint64   // latest
	PendingNonce   uint64
	Tip            *big.Int
	BaseFee        *big.Int // nil header base fee if NoBaseFee
	NoBaseFee      bool
	Gas            uint64
	EstimateErr    bool
	SendErr        bool
	ReceiptStatus  uint64
	NoReceipt      bool

	Sent []*types.Transaction
	srv  *httptest.Server
}

// New starts an honest fake for the given chain.
func New(chainID uint64) *Fake {
	f := &Fake{
		ChainID: chainID, BalanceMicro: 5_000_000, Tip: big.NewInt(100_000_000),
		BaseFee: big.NewInt(20_000_000_000), Gas: 60_000, ReceiptStatus: 1,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// URL is the endpoint to dial.
func (f *Fake) URL() string { return f.srv.URL }

// Close stops the server.
func (f *Fake) Close() { f.srv.Close() }

// Broadcasts returns the transactions the fake was asked to send.
func (f *Fake) Broadcasts() []*types.Transaction {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*types.Transaction(nil), f.Sent...)
}

// Set changes the fake's behaviour under its lock.
func (f *Fake) Set(fn func(*Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type req struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) > 0 && body[0] == '[' {
		var reqs []req
		_ = json.Unmarshal(body, &reqs)
		out := make([]json.RawMessage, 0, len(reqs))
		for _, q := range reqs {
			out = append(out, f.answer(q))
		}
		b, _ := json.Marshal(out)
		_, _ = w.Write(b)
		return
	}
	var q req
	_ = json.Unmarshal(body, &q)
	_, _ = w.Write(f.answer(q))
}

func (f *Fake) answer(q req) json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	res, errMsg := f.result(q)
	var out map[string]interface{}
	if errMsg != "" {
		out = map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "error": map[string]interface{}{"code": -32000, "message": errMsg}}
	} else {
		out = map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": res}
	}
	b, _ := json.Marshal(out)
	return b
}

func (f *Fake) native() *big.Int {
	if f.NativeOverride != nil {
		return f.NativeOverride
	}
	n := new(big.Int).Mul(new(big.Int).SetUint64(f.BalanceMicro), new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil))
	if f.NativeDust != nil {
		n.Add(n, f.NativeDust)
	}
	return n
}

func (f *Fake) result(q req) (interface{}, string) {
	switch q.Method {
	case "eth_chainId":
		return hexutil.Uint64(f.ChainID), ""
	case "eth_call": // balanceOf
		return hexutil.Bytes(common.LeftPadBytes(new(big.Int).SetUint64(f.BalanceMicro).Bytes(), 32)), ""
	case "eth_getBalance":
		return (*hexutil.Big)(f.native()), ""
	case "eth_getTransactionCount":
		var tag string
		if len(q.Params) > 1 {
			_ = json.Unmarshal(q.Params[1], &tag)
		}
		if tag == "pending" {
			return hexutil.Uint64(f.PendingNonce), ""
		}
		return hexutil.Uint64(f.Nonce), ""
	case "eth_maxPriorityFeePerGas":
		return (*hexutil.Big)(f.Tip), ""
	case "eth_getBlockByNumber":
		h := &types.Header{Number: big.NewInt(100), Difficulty: big.NewInt(0), GasLimit: 30_000_000, Time: 1_790_000_000}
		if !f.NoBaseFee {
			h.BaseFee = f.BaseFee
		}
		return h, ""
	case "eth_estimateGas":
		if f.EstimateErr {
			return nil, "execution reverted"
		}
		return hexutil.Uint64(f.Gas), ""
	case "eth_sendRawTransaction":
		if f.SendErr {
			return nil, "rejected"
		}
		var raw hexutil.Bytes
		_ = json.Unmarshal(q.Params[0], &raw)
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			return nil, fmt.Sprintf("bad tx: %v", err)
		}
		f.Sent = append(f.Sent, tx)
		return tx.Hash(), ""
	case "eth_getTransactionReceipt":
		if f.NoReceipt || len(f.Sent) == 0 {
			return nil, ""
		}
		tx := f.Sent[len(f.Sent)-1]
		rc := &types.Receipt{Status: f.ReceiptStatus, CumulativeGasUsed: 50_000, GasUsed: 50_000,
			TxHash: tx.Hash(), BlockNumber: big.NewInt(101), BlockHash: common.Hash{1}, Logs: []*types.Log{}}
		return rc, ""
	}
	return nil, "method not supported by fake: " + q.Method
}

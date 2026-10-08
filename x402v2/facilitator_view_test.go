//go:build arc

package x402v2

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/rudizee007/spt-txn-x402-arc/intent"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009"
	"github.com/rudizee007/spt-txn-x402-arc/settle/eip3009/eip3009sign"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// requirementsV2 mirrors the reference server's PaymentRequirements
// (x402-foundation/x402 @ 7f2b2f1, go/types/v2.go).
type requirementsV2 struct {
	Scheme            string                 `json:"scheme"`
	Network           string                 `json:"network"`
	Asset             string                 `json:"asset"`
	Amount            string                 `json:"amount"`
	PayTo             string                 `json:"payTo"`
	MaxTimeoutSeconds int                    `json:"maxTimeoutSeconds"`
	Extra             map[string]interface{} `json:"extra,omitempty"`
}

// referenceMatch reproduces paymentRequirementsMatchAccepted and DeepEqual from
// the same commit (go/server.go, go/types.go): core terms equal after a JSON
// round-trip, server extra a subset of accepted extra. Reproduced, not
// imported, so the test needs no dependency on the reference.
func referenceMatch(required, accepted requirementsV2) bool {
	rc, ac := required, accepted
	rc.Extra, ac.Extra = nil, nil
	a, _ := json.Marshal(rc)
	b, _ := json.Marshal(ac)
	if string(a) != string(b) {
		return false
	}
	for k, v := range required.Extra {
		if accepted.Extra[k] != v {
			return false
		}
	}
	return true
}

func TestFacilitatorViewOfThePayload(t *testing.T) {
	key, _ := crypto.GenerateKey()
	from := evm.Address(crypto.PubkeyToAddress(key.PublicKey))
	b, err := eip3009.Bind(eip3009.Binding{
		Domain: eip3009.Domain{Name: "USDC", Version: "2", ChainID: 5042002, VerifyingContract: usdc},
		From:   from, To: merchant, Value: big.NewInt(500_000), Intent: intent.Digest{9},
		CapabilityExpiry: time.Now().Add(time.Hour), CallExpiry: time.Now().Add(time.Minute), MaxLifetime: 2 * time.Minute,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := eip3009sign.Sign(b, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(cfg, b, s, from, []byte(goodAccepted), []byte(goodResource))
	if err != nil {
		t.Fatal(err)
	}

	// What a resource server and facilitator receive: the header.
	raw, err := base64.StdEncoding.DecodeString(p.Header)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		X402Version int            `json:"x402Version"`
		Accepted    requirementsV2 `json:"accepted"`
		Payload     struct {
			Signature     string            `json:"signature"`
			Authorization map[string]string `json:"authorization"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &got); err != nil || got.X402Version != 2 {
		t.Fatalf("decode: %v", err)
	}

	// 1. The server's own requirements match the payload's accepted exactly.
	var published requirementsV2
	_ = json.Unmarshal([]byte(goodAccepted), &published)
	if !referenceMatch(published, got.Accepted) {
		t.Fatal("the reference matcher does not find the server's requirements in the payload")
	}
	// ...and a re-cased (checksummed) payTo would NOT have matched: the reason
	// for exact echo.
	recased := got.Accepted
	recased.PayTo = common.HexToAddress(recased.PayTo).Hex()
	if referenceMatch(published, recased) {
		t.Fatal("expected a re-cased payTo to fail the reference matcher")
	}

	// 2. The signature verifies under the domain the payload itself states
	// (extra.name/version, asset, network), computed by go-ethereum.
	auth := got.Payload.Authorization
	td := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {{Name: "name", Type: "string"}, {Name: "version", Type: "string"}, {Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"}},
			"TransferWithAuthorization": {{Name: "from", Type: "address"}, {Name: "to", Type: "address"}, {Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"}, {Name: "validBefore", Type: "uint256"}, {Name: "nonce", Type: "bytes32"}},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{Name: got.Accepted.Extra["name"].(string), Version: got.Accepted.Extra["version"].(string),
			ChainId: (*math.HexOrDecimal256)(big.NewInt(int64(mustChain(t, got.Accepted.Network)))), VerifyingContract: got.Accepted.Asset},
		Message: apitypes.TypedDataMessage{"from": auth["from"], "to": auth["to"], "value": auth["value"],
			"validAfter": auth["validAfter"], "validBefore": auth["validBefore"], "nonce": auth["nonce"]},
	}
	h, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := common.FromHex(got.Payload.Signature)
	sigBytes[64] -= 27
	pub, err := crypto.SigToPub(h, sigBytes)
	if err != nil || !strings.EqualFold(crypto.PubkeyToAddress(*pub).Hex(), auth["from"]) {
		t.Fatalf("signature does not recover to authorization.from under the payload's own domain: %v", err)
	}
	// 3. The facilitator's EIP-3009 checks: to == payTo, value == amount.
	if !strings.EqualFold(auth["to"], got.Accepted.PayTo) || auth["value"] != got.Accepted.Amount {
		t.Fatal("authorization and accepted terms disagree")
	}
}

func mustChain(t *testing.T, network string) uint64 {
	t.Helper()
	n, ok := caip2Chain(network)
	if !ok {
		t.Fatalf("network %q", network)
	}
	return n
}

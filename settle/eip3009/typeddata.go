package eip3009

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// TypedDataJSON is the EIP-712 typed-data document for the constructed
// authorization, as a wallet provider's sign-typed-data endpoint takes it (the
// C4 fallback, SPEC-ARC-M3 §4.2). The provider's signature is accepted only if
// it recovers to the payer over Bound.Digest(), so a provider that hashes this
// document differently produces a refusal, never a different payment.
func (b Bound) TypedDataJSON() ([]byte, error) {
	if !b.ok {
		return nil, ErrNotBound
	}
	a := b.auth
	type field struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	doc := map[string]interface{}{
		"types": map[string][]field{
			"EIP712Domain": {{"name", "string"}, {"version", "string"}, {"chainId", "uint256"}, {"verifyingContract", "address"}},
			PrimaryType: {{"from", "address"}, {"to", "address"}, {"value", "uint256"},
				{"validAfter", "uint256"}, {"validBefore", "uint256"}, {"nonce", "bytes32"}},
		},
		"primaryType": PrimaryType,
		"domain": map[string]interface{}{
			"name": a.Domain.Name, "version": a.Domain.Version,
			"chainId":           json.Number(strconv.FormatUint(a.Domain.ChainID, 10)),
			"verifyingContract": a.Domain.VerifyingContract.Hex(),
		},
		"message": map[string]string{
			"from": a.From.Hex(), "to": a.To.Hex(), "value": a.Value.String(),
			"validAfter": a.ValidAfter.String(), "validBefore": a.ValidBefore.String(),
			"nonce": "0x" + hex.EncodeToString(a.Nonce[:]),
		},
	}
	return json.Marshal(doc)
}

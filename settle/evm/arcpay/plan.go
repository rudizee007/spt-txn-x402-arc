//go:build arc

// Package arcpay is the Arc settlement path shared by cmd/payarc and
// cmd/arc-gateway: build the transaction, assert it with the settle/evm guard,
// sign, re-check the signed transaction, broadcast, and wait for inclusion
// (docs/SPEC-X402-ARC.md §A.4; docs/SPEC-ARC-GATE.md §4). The code was moved
// here from cmd/payarc, not rewritten, so both commands run one implementation.
//
// It is behind the `arc` build tag because it links go-ethereum, and must be
// built with CGO_ENABLED=0 (nocgo.go).
package arcpay

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
)

// Plan holds everything a transaction is built from. The fields after Tip exist
// so cmd/payarc's adversarial modes can change exactly one thing while the
// build path stays identical; Settle never sets them. Whatever a Plan builds,
// the guard sees the built object, never the Plan.
type Plan struct {
	Asset    common.Address
	Merchant common.Address
	Payer    common.Address
	Amount   *big.Int
	Nonce    uint64
	GasLimit uint64
	FeeCap   *big.Int
	Tip      *big.Int

	// ChainBase is the selected network's chain id. It has no default: a plan
	// built without one carries chain id 0, which the guard refuses.
	ChainBase uint64

	// Adversarial knobs (cmd/payarc -tamper, -selftest).
	Legacy          bool
	ChainIDOverride *big.Int
	NativeValue     *big.Int
	ToOverride      *common.Address
	DataOverlay     func([]byte) []byte
	AccessList      types.AccessList
}

func (p Plan) chain() *big.Int {
	if p.ChainIDOverride != nil {
		return p.ChainIDOverride
	}
	return new(big.Int).SetUint64(p.ChainBase)
}

// Value is the native value the plan attaches: zero unless a knob set it.
func (p Plan) Value() *big.Int {
	if p.NativeValue != nil {
		return p.NativeValue
	}
	return big.NewInt(0)
}

// To is the call target: the USDC contract unless a knob overrode it.
func (p Plan) To() *common.Address {
	if p.ToOverride != nil {
		return p.ToOverride
	}
	a := p.Asset
	return &a
}

// Calldata is the ERC-20 transfer the plan pays with.
func (p Plan) Calldata() ([]byte, error) {
	data, err := evm.EncodeTransfer(evm.Address(p.Merchant), p.Amount)
	if err != nil {
		return nil, fmt.Errorf("encode transfer: %w", err)
	}
	if p.DataOverlay != nil {
		return p.DataOverlay(data), nil
	}
	return data, nil
}

// Build returns the unsigned transaction the plan describes.
func (p Plan) Build() (*types.Transaction, error) {
	data, err := p.Calldata()
	if err != nil {
		return nil, err
	}
	if p.Legacy {
		return types.NewTx(&types.LegacyTx{
			Nonce: p.Nonce, GasPrice: p.FeeCap, Gas: p.GasLimit,
			To: p.To(), Value: p.Value(), Data: data,
		}), nil
	}
	return types.NewTx(&types.DynamicFeeTx{
		ChainID: p.chain(), Nonce: p.Nonce,
		GasTipCap: p.Tip, GasFeeCap: p.FeeCap, Gas: p.GasLimit,
		To: p.To(), Value: p.Value(), Data: data,
		AccessList: p.AccessList,
	}), nil
}

// ViewOf reads the guard's view off the real transaction object: every field
// from an accessor, none from what we meant to build. That is what makes the
// assertion an assertion about the thing that will be signed rather than about
// a parallel copy of our intentions.
func ViewOf(tx *types.Transaction, signer evm.Address) (evm.Transaction, error) {
	var to *evm.Address
	if t := tx.To(); t != nil {
		a := evm.Address(*t)
		to = &a
	}
	chainID := tx.ChainId()
	// Never nil in go-ethereum. This catches a chain id past 2^64; an
	// unprotected legacy transaction derives a large nonsense chain id from
	// V and is refused by §A.4 assertion 1 on the type, not here.
	if chainID == nil || !chainID.IsUint64() {
		return evm.Transaction{}, fmt.Errorf("transaction carries an unusable chain id %v", chainID)
	}
	return evm.Transaction{
		Type:                 tx.Type(),
		ChainID:              chainID.Uint64(),
		Nonce:                tx.Nonce(),
		GasLimit:             tx.Gas(),
		MaxFeePerGas:         tx.GasFeeCap(),
		To:                   to,
		Value:                tx.Value(),
		Data:                 tx.Data(),
		AccessListLen:        len(tx.AccessList()),
		AuthorizationListLen: len(tx.SetCodeAuthorizations()),
		BlobHashLen:          len(tx.BlobHashes()),
		Signer:               signer,
	}, nil
}

// ── the selected network ────────────────────────────────────────────────────
//
// Everything a network selection decides is built here, from the one selected
// profile, so a test can check that the binding, the signer, the plan and the
// endpoint check all name the same chain. The testnet and mainnet USDC
// addresses are identical, so the chain id is the only thing keeping a
// settlement on the network the operator named (SPEC-X402-ARC §A.1).

// NewBinding binds the payment to the selected network's chain id and USDC.
func NewBinding(net evm.ArcNetwork, merchant, payer common.Address, amount *big.Int, nonce uint64, maxGasCost *big.Int) (evm.BoundPayment, error) {
	return evm.NewBoundPayment(evm.Binding{
		ChainID:    net.ChainID,
		Asset:      net.USDC.AccountID32(),
		PayTo:      evm.Address(merchant).AccountID32(),
		Payer:      evm.Address(payer).AccountID32(),
		Amount:     new(big.Int).Set(amount),
		Nonce:      nonce,
		MaxGasCost: maxGasCost,
	})
}

// NewSigner returns a signer whose chain id, the one hashed into the EIP-155
// signing preimage, is the selected network's.
func NewSigner(net evm.ArcNetwork) types.Signer {
	return types.LatestSignerForChainID(new(big.Int).SetUint64(net.ChainID))
}

// NewPlan returns the untampered transaction plan for the selected network.
func NewPlan(net evm.ArcNetwork, merchant, payer common.Address, amount *big.Int, nonce uint64, feeCap, tip *big.Int) Plan {
	return Plan{
		Asset: common.Address(net.USDC), Merchant: merchant, Payer: payer,
		Amount: new(big.Int).Set(amount), Nonce: nonce,
		FeeCap: feeCap, Tip: tip, ChainBase: net.ChainID,
	}
}

// ErrWrongNetwork reports an endpoint serving a chain other than the selected one.
var ErrWrongNetwork = errors.New("endpoint is on a different network")

// CheckEndpointChain refuses an endpoint whose eth_chainId is not the selected
// network's. The chain id is configuration; a disagreeing endpoint is refused,
// never adopted (§A.5.12).
func CheckEndpointChain(net evm.ArcNetwork, reported *big.Int) error {
	if reported == nil || !reported.IsUint64() || reported.Uint64() != net.ChainID {
		return fmt.Errorf("%w: it reports chain id %v, network %s is bound to %d; refusing to settle",
			ErrWrongNetwork, reported, net.Name, net.ChainID)
	}
	return nil
}

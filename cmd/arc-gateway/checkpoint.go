//go:build arc

package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rudizee007/spt-txn-pep/translog"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm"
	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// checkpointMaxFeeMicro is the ceiling on one checkpoint's fee: 0.02 USDC.
// A checkpoint costs a fraction of a cent at current Arc prices.
const checkpointMaxFeeMicro = 20_000

// checkpointer publishes the log head on Arc (SPEC-ARC-GATE §5). A checkpoint
// is evidence publication, not authorization: a failure is reported and
// retried at the next trigger, and never blocks or changes a decision.
type checkpointer struct {
	net       evm.ArcNetwork
	client    *ethclient.Client
	key       *ecdsa.PrivateKey
	log       *translog.Log
	every     int
	since     int
	published int // log size at the last successful checkpoint; -1 before any
	diag      io.Writer
}

func newCheckpointer(net evm.ArcNetwork, c *ethclient.Client, k *ecdsa.PrivateKey, l *translog.Log, every int, diag io.Writer) *checkpointer {
	return &checkpointer{net: net, client: c, key: k, log: l, every: every, published: -1, diag: diag}
}

// maybePublish is called after every recorded decision.
func (c *checkpointer) maybePublish() {
	c.since++
	if c.since < c.every {
		return
	}
	if c.publish(30*time.Second, false) == nil {
		c.since = 0
	}
}

// publishNow checkpoints the current head, if it has not been published, and
// waits for inclusion. Used at clean shutdown.
func (c *checkpointer) publishNow() {
	_ = c.publish(2*time.Minute, true)
}

func (c *checkpointer) publish(timeout time.Duration, wait bool) error {
	root, n := c.log.Head()
	if n == 0 || n == c.published {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	hash, err := c.send(ctx, uint64(n), root, wait)
	if err != nil {
		fmt.Fprintf(c.diag, "checkpoint of %d entries not published (will retry): %v\n", n, err)
		return err
	}
	c.published = n
	fmt.Fprintf(c.diag, "checkpoint: %d entries, root %x, tx %s%s\n", n, root, c.net.ExplorerTxPrefix, hash.Hex())
	return nil
}

func (c *checkpointer) send(ctx context.Context, n uint64, root [32]byte, wait bool) (common.Hash, error) {
	from := crypto.PubkeyToAddress(c.key.PublicKey)
	reported, err := c.client.ChainID(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	if err := arcpay.CheckEndpointChain(c.net, reported); err != nil {
		return common.Hash{}, err
	}
	nonce, err := arcpay.BoundNonce(ctx, c.client, from)
	if err != nil {
		return common.Hash{}, err
	}
	tip, err := c.client.SuggestGasTipCap(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	head, err := c.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return common.Hash{}, err
	}
	if head.BaseFee == nil {
		return common.Hash{}, fmt.Errorf("latest header carries no base fee")
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	data := evm.CheckpointData(n, root)
	gas, err := c.client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &from, Value: big.NewInt(0), Data: data})
	if err != nil {
		return common.Hash{}, fmt.Errorf("estimate gas: %w", err)
	}
	if gas > arcpay.MaxGasLimit {
		return common.Hash{}, fmt.Errorf("endpoint estimated %d gas for a checkpoint", gas)
	}
	gas += gas / 5

	b := evm.CheckpointBinding{
		ChainID: c.net.ChainID, From: evm.Address(from), Nonce: nonce, N: n, Root: root,
		MaxGasCost: new(big.Int).Mul(big.NewInt(checkpointMaxFeeMicro), evm.NativeScale()),
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: new(big.Int).SetUint64(c.net.ChainID), Nonce: nonce,
		GasTipCap: tip, GasFeeCap: feeCap, Gas: gas,
		To: &from, Value: big.NewInt(0), Data: data,
	})
	view, err := arcpay.ViewOf(tx, evm.Address(from))
	if err != nil {
		return common.Hash{}, err
	}
	if err := evm.VerifyCheckpoint(view, b); err != nil {
		return common.Hash{}, fmt.Errorf("refusing to sign: %w", err)
	}
	signer := arcpay.NewSigner(c.net)
	signed, err := types.SignTx(tx, signer, c.key)
	if err != nil {
		return common.Hash{}, err
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return common.Hash{}, err
	}
	signedView, err := arcpay.ViewOf(signed, evm.Address(sender))
	if err != nil {
		return common.Hash{}, err
	}
	if err := evm.VerifyCheckpoint(signedView, b); err != nil {
		return common.Hash{}, fmt.Errorf("refusing to broadcast: %w", err)
	}
	if err := c.client.SendTransaction(ctx, signed); err != nil {
		return common.Hash{}, err
	}
	if wait {
		if _, err := bindWait(ctx, c.client, signed); err != nil {
			return signed.Hash(), err
		}
	}
	return signed.Hash(), nil
}

func bindWait(ctx context.Context, c *ethclient.Client, tx *types.Transaction) (*types.Receipt, error) {
	r, err := bind.WaitMined(ctx, c, tx)
	if err != nil {
		return nil, err
	}
	if r.Status != types.ReceiptStatusSuccessful {
		return r, fmt.Errorf("checkpoint %s reverted", tx.Hash().Hex())
	}
	return r, nil
}

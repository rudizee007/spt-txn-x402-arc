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

// pendingTimeout is how long a sent checkpoint may go unseen before it is
// dropped, unrecorded, and its head becomes eligible to be sent again.
const pendingTimeout = 10 * time.Minute

// checkpointMinInterval spaces triggered checkpoints, so an agent that floods
// the server with calls cannot spend the checkpoint key's gas faster than one
// checkpoint a minute.
const checkpointMinInterval = time.Minute

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
	published int    // log size at the last checkpoint, this run or recorded; 0 if none
	headPath  string // where each mined head is recorded (§6)
	pending   *pendingHead
	last      time.Time
	savedSize func() int // log size at the last successful save
	now       func() time.Time
	diag      io.Writer
}

// pendingHead is a checkpoint that has been sent and not yet seen mined. It is
// recorded only once it is mined.
type pendingHead struct {
	n    int
	root [32]byte
	tx   common.Hash
	prev int // published before this head was sent
	sent time.Time
}

// newCheckpointer starts from the recorded head, so a head already on chain is
// not published again after a restart.
func newCheckpointer(net evm.ArcNetwork, c *ethclient.Client, k *ecdsa.PrivateKey, l *translog.Log, every int, savedSize func() int,
	published int, headPath string, diag io.Writer) *checkpointer {
	return &checkpointer{net: net, client: c, key: k, log: l, every: every, published: published, headPath: headPath, savedSize: savedSize, now: time.Now, diag: diag}
}

// maybePublish is called after every recorded decision. It first records a
// sent checkpoint that has since been mined, without waiting, so the record
// trails the chain by at most the checkpoint still pending.
func (c *checkpointer) maybePublish() {
	if c.pending != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c.confirm(ctx, false)
		cancel()
	}
	c.since++
	if c.since < c.every || time.Since(c.last) < checkpointMinInterval {
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c.confirm(ctx, wait)
	root, n := c.log.Head()
	if n <= 0 || n == c.published {
		return nil
	}
	// One checkpoint in flight at a time: a new head waits until the previous
	// one is seen mined or reverted, so the record trails by at most one.
	if c.pending != nil {
		err := fmt.Errorf("checkpoint of %d entries (tx %s) not yet seen mined", c.pending.n, c.pending.tx.Hex())
		_, _ = fmt.Fprintf(c.diag, "checkpoint of %d entries deferred: %v\n", n, err)
		return err
	}
	// Only a head that is on disk is published. Anchoring an unsaved head
	// would, after a restart, show two roots on chain for one log size.
	if n != c.savedSize() {
		err := fmt.Errorf("head of %d entries is not saved (saved: %d)", n, c.savedSize())
		_, _ = fmt.Fprintf(c.diag, "checkpoint skipped: %v\n", err)
		return err
	}
	hash, err := c.send(ctx, uint64(n), root) // #nosec G115 -- n > 0, checked above
	if err != nil {
		_, _ = fmt.Fprintf(c.diag, "checkpoint of %d entries not published (will retry): %v\n", n, err)
		return err
	}
	c.pending = &pendingHead{n: n, root: root, tx: hash, prev: c.published, sent: c.now()}
	c.published = n
	c.last = time.Now()
	_, _ = fmt.Fprintf(c.diag, "checkpoint: %d entries, root %x, tx %s%s\n", n, root, c.net.ExplorerTxPrefix, hash.Hex())
	if wait {
		c.confirm(ctx, true)
	}
	return nil
}

// confirm records the pending checkpoint once it is mined. Until then it is
// not recorded, so a restart publishes that head again rather than treating a
// transaction that may have been dropped as on chain. A reverted checkpoint is
// retried at the next trigger.
func (c *checkpointer) confirm(ctx context.Context, wait bool) {
	p := c.pending
	if p == nil {
		return
	}
	var r *types.Receipt
	var err error
	if wait {
		r, err = bind.WaitMinedHash(ctx, c.client, p.tx)
	} else {
		r, err = c.client.TransactionReceipt(ctx, p.tx)
	}
	if err != nil || r == nil {
		if c.now().Sub(p.sent) > pendingTimeout {
			c.pending = nil
			c.published = p.prev
			_, _ = fmt.Fprintf(c.diag, "checkpoint of %d entries (tx %s) not seen mined after %s; it will be sent again\n", p.n, p.tx.Hex(), pendingTimeout)
		}
		return
	}
	c.pending = nil
	if r.Status != types.ReceiptStatusSuccessful {
		c.published = p.prev
		_, _ = fmt.Fprintf(c.diag, "checkpoint of %d entries reverted (tx %s); it will be sent again\n", p.n, p.tx.Hex())
		return
	}
	if err := saveCheckpointHead(c.headPath, p.n, p.root, p.tx); err != nil {
		_, _ = fmt.Fprintf(c.diag, "checkpoint of %d entries is mined but was not recorded (%v); a restart will publish it again\n", p.n, err)
	}
}

func (c *checkpointer) send(ctx context.Context, n uint64, root [32]byte) (common.Hash, error) {
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
	return signed.Hash(), nil
}

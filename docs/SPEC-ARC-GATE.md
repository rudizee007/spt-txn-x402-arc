# SPEC: gate-driven USDC settlement on Arc, with log checkpoints on Arc

Status: DRAFT for maintainer review. No code is written against it until it is
approved. Companion to [`SPEC-X402-ARC.md`](SPEC-X402-ARC.md), whose §A.4
assertions this document reuses unchanged.

## 1. What this adds

`cmd/payarc` settles a payment the operator types on the command line. This
spec takes the payment from a live policy decision instead:

1. A thin MCP server (`cmd/arc-gateway`) gives an agent runtime one tool,
   `authorize_payment`.
2. Each tool-call is evaluated by the SPT-Txn enforcement point
   (`spt-txn-pep/mcpgate`) against one capability a human approved.
3. Only an ALLOW that has been written to the transparency log reaches
   settlement, and settlement runs through the unchanged pre-sign guard.
4. The log's head (record count and root) is written to Arc periodically, so a
   third party can check the log against the chain.

**Shape: enforcement in one place, thin servers per chain.** The Arc server is
deliberately thin. It holds the MCP protocol handling, the capability file and
the Arc settler, and nothing else that decides. Security-relevant logic is not
copied into it:

- the authorization decision and the log come from `spt-txn-pep` (`mcpgate`,
  `translog` v0.6.0);
- the parser that turns an agent's decimal amount into micro-USDC moves into
  `spt-txn-pep` as a small shared package (§4a), so every chain's server uses
  one implementation and a fix lands once;
- the pre-sign guard is the one `cmd/payarc` already uses (§4).

**Planned later, not part of this spec:** the same Arc server sits behind the
full SPT-Txn MCP enforcement point (`spt-poc` `cmd/mcp-pep`), which verifies a
transaction-scoped token bound to each tool-call. At that point the per-chain
server stops making the policy decision and only settles an already-authorized
call. Nothing in this spec may assume or block that move: the settler's input is
an authorized call and its result, whichever enforcement point produced them.

## 2. Invariants

**I1. One source for the payment.** The recipient, asset and amount that the
guard binds are derived from the tool-call the enforcement point authorized,
and from nothing else. There is no second parse of the agent's arguments on
the settlement path.

**I2. No ALLOW, no signature.** The server hands a payment to settlement only
when the enforcement point's result is `Result.Allowed()` (an ALLOW class with a
log locator), and the settler itself refuses a missing authorization marker or
expiry. Both checks run before the payment key is used for anything, and each
has its own test. The marker is a correlation handle, not proof of
authorization: the proof is the enforcement point's decision and its log entry.

**I3. Two independent controls.** The enforcement point decides; the §A.4 guard
asserts the exact transaction before signing and re-checks it after signing.
Removing either one must leave the other able to refuse on its own, and each has
its own failing test.

**I4. Deny by default, fail closed.** A missing or unreadable capability, key,
log file, endpoint or network setting stops startup. A settlement error after an
ALLOW is reported as an error; it never retries with different values.

**I5. The capability cannot outlive its expiry.** Every tool-call's expiry is
the earlier of (now + 60 s) and the capability's own expiry. An expired
capability refuses every call.

**I6. Checkpoint transactions cannot move USDC.** They are built and asserted by
a separate guard (§5) that refuses any transaction other than the exact
checkpoint shape, and they are signed with a key that is not the payment key.

## 3. The approved capability

A JSON file written by the human operator, read once at startup:

| Field | Meaning |
|---|---|
| `network` | exactly `testnet` or `mainnet` (§A.1; mainnet is never a default) |
| `recipient` | 0x EVM address the payment may go to |
| `resource` | resource identifier, bound byte-exact |
| `max_amount_micro` | ceiling in micro-USDC, a positive integer |
| `expires_at` | RFC 3339 time; required |
| `max_payments` | how many ALLOWs the capability may issue; optional, default 1 |

Every key must be spelled exactly as above and appear once: the file is
scanned before it is decoded, because the JSON decoder would otherwise accept a
case-folded duplicate (`"Recipient"`) and let it silently replace the value a
person reading the file sees. Unknown fields are refused.

`max_payments` is enforced inside the enforcement point's policy, so a refusal
for a used-up capability is a recorded DENY like any other. It is a count of
authorizations, not a spending budget. An ALLOW is counted as soon as it is
issued, before it is persisted, and the count is saved in the gateway's state
directory (`-state-dir`, required, with no default; on Linux
`/var/lib/spt-txn-arc/state`) under the SHA-256 of the capability file's exact
bytes. A missing or empty `-state-dir` stops startup.
The count belongs to the capability, not to a log: every gateway on the machine
account that uses the same capability file meets the same count, whatever `-log`
it names. A restart, whoever causes it, resumes it; a different capability file,
including a reformatted copy of the same one, is a new approval with its own
count. The count is also written beside the log, per capability
(`<log>.<digest>.count`), and at startup the higher is used (an unkeyed
`<log>.count` from an earlier version is read too, and never written), so a
gateway on the same log with a different `-state-dir` still sees it. Startup
prints the state directory in use. A gateway started with both a different
`-state-dir` and a different `-log`, or under another user account, keeps its
own count: run every gateway for one capability with the same state directory.
The asset is always the selected network's USDC; it is not configurable. The
recipient is carried to the enforcement point in the transport form of §A.2
(base58 of the 32-byte widened account id).

The count in force is the highest of three: the keyed copy in the state
directory, the keyed copy beside the log, and a legacy unkeyed `<log>.count`. A
restored higher count is honoured on purpose, even though it can exhaust the
approval with no matching ALLOWs in this log; a restored lower count is ignored.
That is conservative against over-spend.

## 4. Settlement package

`settle/evm/arcpay` (build tag `arc`) holds the build, guard, sign, re-check and
broadcast sequence now inside `cmd/payarc`, moved rather than rewritten, so both
commands share one implementation. It does not import `mcpgate`: its input is a
plain, already-authorized payment, so it can serve this server now and a server
behind a different enforcement point later. The thin server converts the
enforcement point's authorized call into that input, and the conversion is the
only place the two meet.

The settler's entry point:

- Refuses unless the caller passes an authorization marker (the log locator of
  the ALLOW), and refuses an empty one (I2).
- Takes the one recipient the human approved as an address, re-encodes it in
  the §A.2 transport form and compares it with the authorized call's recipient,
  refusing on any difference. There is deliberately no base58 decoder in this
  repository: one encoding direction, one implementation
  (`settle/evm/binding.go`).
- Refuses unless the call's asset is the selected network's USDC in transport
  form.
- Takes the amount as the micro-USDC integer the enforcement point authorized,
  as a base-10 string with no sign, leading zero or overflow, and refuses zero.
- Takes everything network-dependent from the one selected profile
  (`cmd/payarc/network.go`, moved alongside).
- Performs exactly the nonce, endpoint chain-id and native/ERC-20 checks, the fee
  ceiling and the post-sign re-check that `cmd/payarc` performs today.

## 4a. Shared amount parser

The decimal-USDC-to-micro-USDC parser currently inside
`spt-txn-x402-solana/cmd/mcp-gateway` moves to `spt-txn-pep` as a package with no
dependencies, unchanged in grammar:

```
amount = int [ "." frac ]
int    = "0" / ( %x31-39 *DIGIT )
frac   = 1*6DIGIT
```

No sign, no exponent, no leading zeros, at most six decimal places, checked
overflow, and zero refused. An omitted amount is refused before the parser is
called. The move carries the existing tests with it, plus a table test shared by
every caller. The Solana server switches to the shared package in its own later
change; this spec only requires the Arc server to use it.

**Bounded by the authorization's expiry.** The settler receives the call's
expiry (`NotAfter`). Every endpoint call before signing runs under that
deadline, and the expiry is checked again immediately before the signature, so a
slow or hostile endpoint cannot have a payment signed after its authorization
lapsed. Confirmation after broadcast is not bounded by it.

**Nonce.** The settler refuses a gap between the endpoint's confirmed and pending
nonce. Both come from the same endpoint, so a single hostile endpoint can still
report a future nonce for both and hold a correctly bound signed payment until
the payer's nonce reaches it. An optional second, independent endpoint
(`-verify-rpc`) must then agree on the confirmed nonce; running without one
leaves that residual, and is not recommended on mainnet.

**Lifetime of the signed transaction.** A signed artefact should not outlive the
authorization that produced it. An EIP-1559 transaction carries no expiry field,
so on Arc its lifetime cannot be derived from the authorization's expiry. What
bounds it instead: the signed transaction exists only in memory, is broadcast at
once, and binds a nonce that the payer's next transaction consumes. The residual
is stated here, not hidden: an endpoint that receives the signed transaction and
withholds it can submit it later, until that nonce is used. The gateway reports
a transaction that is broadcast but unconfirmed within its timeout as
unavailable, never as success.

## 5. Log checkpoints on Arc

**What is published.** The log head from `translog` v0.6.0 (`Head()`: the
record count `n` and the root, which binds `n`).

**Transaction shape.** A type-2 transaction on the selected network from the
checkpoint key's address to the same address, value 0, empty access and
authorization lists, with data exactly:

```
"spt-txn/translog-checkpoint/v1" (30 ASCII bytes) || n (uint64, big-endian) || root (32 bytes)
```

70 bytes in total. A reader recovers `n` and the root from the explorer or any
node; the log's verifying key is published in the repository README.

**Checkpoint guard.** A separate function asserts, on the transaction about to
be signed and again after signing: type 2, chain id, nonce, `to` equals the
checkpoint address, value 0, empty lists, data equal byte-for-byte to the
expected 70 bytes, and gas limit times max fee within its own ceiling. It shares
no code path with the payment guard's binding, so neither can be loosened
through the other.

**When.** After every N recorded decisions (default 10), at most once a minute,
and on shutdown; never twice for the same head, and only for a head that has
been saved, so a restart cannot leave two roots on chain for one log size. The
checkpoint runs after the call that triggered it has been answered, so it never
delays a payment. A failed checkpoint is logged to stderr and retried at the
next trigger; it never changes a decision, because a checkpoint is evidence
publication, not authorization. The minimum interval bounds how fast an agent
flooding the server with calls can spend the checkpoint key's gas.

**Key.** Its own key file, separate from the payment key and from the log
signing key (three keys, three roles). It holds only enough USDC for gas. One
checkpoint key serves one log: the checkpoint data does not name the log, so
two logs checkpointed by one key would put two roots for one size under the
same sender.

## 6. Log persistence

The log signing key and the log itself are files. The log is saved after every
append, before the tool-call returns; if the save fails, the call returns an
error and settlement does not run. The payment count is written first, then the
log, so an interruption between the two leaves the count at or above the ALLOWs
in the log, never below. Both counts are also written once at startup, so a
location that cannot be written or synced stops startup rather than every later
call. On restart the log is loaded and verified
(`translog.LoadLog`) before the server accepts a call.

**One gateway per log, and per capability.** At startup the gateway takes two
exclusive, non-blocking locks before it reads the log, the payment count or the
checkpoint record, and holds both until it exits: `<log>.lock` beside the log,
and `<digest>.lock` in the state directory for the capability. If either is
held, startup refuses. It also refuses if a lock file's name stops referring to
the file it locked. Before every save of a decision the gateway checks again
that both lock files are still the files it locked; if either is gone or
replaced, nothing is saved and nothing is settled. The locks are the operating
system's advisory `flock`: it binds every gateway on one machine, not processes
that ignore it. On a platform without `flock` the gateway refuses to start.

**Paths.** `-log` and `-state-dir` must be absolute paths; an empty or relative
one is refused, and so is a `-state-dir` that is the root directory. Paths are
cleaned before anything else, so a `..` is removed lexically. The gateway then
walks the directory holding the log, the state directory, and the directory
holding each key file, one component at a time from the root, and opens every
file through the path that walk resolved. Every directory above the last one
must be owned by the operator account or root and must not be writable by group
or others unless its sticky bit is set (for example a real, sticky
world-writable `/tmp`). The last directory must be owned by the operator account
or root and must not be writable by group or others at all; a sticky bit does
not change that. It is judged from the same lookup the walk made, not a second
one. A symlink on the path is followed only if the link is owned by root and the
directory holding it has already passed these rules, as with `/home` linked to
`/usr/home` on FreeBSD or `/tmp` and `/var` on macOS; the walk then continues at
the link's target, which is checked in full, and more than 40 links refuse the
path. Any other symlink is refused. `-log` itself must not be a symlink. The
state directory, if missing, is created with mode 0700 only after the directory
above it has passed the walk, and its parent must already exist.

**Design boundaries.** These are decided, not deferred:
- **Ownership is the control between accounts.** The checks use the owner uid
  and the mode bits only. The gateway's files are assumed to be owned by the
  operator account that runs it; that account also holds the payment key, so
  pinning files by inode or re-checking descriptors would defend only against
  an account that can already sign directly, and is not done.
- **Access control lists are not supported.** An ACL that grants another
  account write access (for example one inherited on macOS) is not detected:
  reading it needs cgo or an external tool, neither of which the trust boundary
  allows.
- **Network and shared file systems are not supported.** `flock` is advisory
  and not reliable on them.
- **A checkpoint not seen mined is sent again.** After a restart, or after ten
  minutes unseen, the same head can be published twice from the checkpoint key.
  A head is only ever sent after it is saved, so this repeats a root and never
  contradicts one; the cost is gas. Recording pending transactions to avoid it
  was considered and not adopted.

**The last checkpoint is remembered.** Once a checkpoint transaction is seen
mined, its size, root and transaction are saved atomically next to the log
(`<log>.checkpoint`). A checkpoint that is sent but not seen mined is not
recorded, and the next run publishes that head again; a reverted one is sent
again. Only one checkpoint is in flight at a time: a newer head waits until the
pending one is seen mined or reverted, or until it has gone unseen for ten
minutes, when it is dropped unrecorded and its head is sent again. The pending
checkpoint is looked for at every decision, after the reply, so the record
trails the chain by at most that one checkpoint: a gateway killed right after
sending one leaves it unrecorded. A head already recorded is not published
again. At startup the gateway refuses if the record names more entries than the
log holds, or if the log's first n entries do not hash to the recorded root.

The record is a local, unsigned file. It detects a log that diverged from it by
accident (a restored or truncated log, a copy from another run); it does not
detect a log and record replaced together, or a record deleted, and it is not a
comparison with the chain. The chain is the authority: a reader checks the log
against the checkpoint transactions, as the README describes. **Recovery**, when
startup refuses on the record: compare the log with the checkpoints on chain.
If the log matches the chain, the record is stale and can be removed; if it does
not, the log is not the published one and must not be used under that log key.

## 6a. Modes, and an evaluate-only mode an agent can verify

The server runs in exactly one of three modes, fixed at startup:

| Mode | Flag | Payment key | Tool | On ALLOW |
|---|---|---|---|---|
| live | (none) | required | `authorize_payment` | settles through the guard |
| dry-run | `-dry-run` | required | `authorize_payment` | runs the guard, signs nothing |
| evaluate-only | `-evaluate-only` | **refused** | `evaluate_payment` | returns the decision, settles nothing |

**Why evaluate-only exists.** A careful agent will not call a tool that can move
funds on an operator's say-so, because it cannot see how the server was started.
In evaluate-only mode the server holds no payment key, so it has nothing to sign
with, and it offers a differently named tool whose description says so. An agent
can probe the policy with no funds at risk, and the refusal it sees is the same
decision, from the same enforcement point, recorded in the same signed log and
checkpointed on Arc, as in live mode.

**Rules.**
- `-evaluate-only` refuses to start if `-key` or `-dry-run` is given. A payment key
  in this mode is a configuration error, not something to ignore. Startup also
  refuses any positional argument, because flag parsing stops there and every
  flag after it, `-evaluate-only` included, would be silently dropped.
- The two tools never coexist: in evaluate-only mode `authorize_payment` is an
  unknown tool, and in live or dry-run mode `evaluate_payment` is.
- Every reply begins with the mode, what an ALLOW does to a payment, and whether
  log checkpoints are published, for example
  `[mode: evaluate-only; payments: no payment key, none can be sent; checkpoints: on, from a separate gas-only key]`,
  so the guarantee is part of the interface. Checkpoints are named because on Arc
  their gas is paid in USDC: "no transaction is sent" would be false.
- A server in any other mode offers no tool and refuses every call, so a wiring
  mistake cannot yield a settling server that describes itself otherwise. A live
  server with no settler reports an error, never an ALLOW.
- An ALLOW in evaluate-only mode is recorded and counts toward `max_payments`, like
  any other ALLOW. An operator who means to settle under a capability later does
  not issue an allowed evaluation under it first.
- Checkpoints work in every mode; the checkpoint key can only publish checkpoints
  (§5).

**Residuals, stated rather than hidden.**
- In evaluate-only mode there is no payment key to compare with, so startup cannot
  refuse a checkpoint key that is in fact the payment wallet's key, as live mode
  does. Such a key could still only publish checkpoints (the §5 guard holds), but
  it would spend the payment wallet's gas and share its nonces with any live
  server using the same wallet.
- The log records the decision, not the mode. An evaluate-only ALLOW and a live
  ALLOW are identical entries; a reader of one log shared across modes cannot tell
  an evaluation from an authorization that was settled. The settlement itself is
  on chain and can be matched to its log entry.

## 7. Out of scope

Multi-capability policies, delegation chains (a later milestone), Circle Wallets
signing (next milestone), and any change to the §A.4 assertions.

## 8. Tests that must exist

Each fails when the control it names is reverted:

1. A DENY never reaches settlement (I2); an ALLOW without a log locator never
   does either.
2. Settlement binds the authorized call's recipient and amount: a test that
   passes different values to the builder is refused by the guard (I1).
3. With the enforcement point replaced by one that always allows, the guard
   still refuses a tampered transaction (I3, guard half).
4. With the guard's transaction builder tampered, the enforcement point still
   refuses a call outside the capability (I3, gate half).
5. Expired capability refuses every call; a call's expiry never exceeds the
   capability's (I5).
6. The checkpoint guard refuses: nonzero value, a different `to`, data off by
   one byte, a USDC transfer's calldata, and a fee over its ceiling; startup
   refuses the payment key in the checkpoint role (I6).
7. A log save failure prevents settlement (§6).
8. Startup refuses a missing or malformed capability, unknown fields, a mainnet
   capability without explicit keys, and a checkpoint key equal to the payment
   key.
9. Evaluate-only (§6a): startup refuses `-key` and `-dry-run` with
   `-evaluate-only`; the server offers `evaluate_payment` and never
   `authorize_payment`, and the live server the reverse; an evaluate-only ALLOW
   never reaches a settler, even one that is present, and is counted; every
   reply begins with the mode line.
10. A second gateway on the same log, or on the same capability with a different
    log, refuses to start while the first holds it, including from a separate
    process, and starts once it has exited; nothing is read before the locks are
    held; the count follows the capability across log paths and is kept beside
    the log too; a state directory others can write to, or a count location
    that cannot be written, is refused at startup; a decision is not saved once
    a lock file is gone or replaced; a count that cannot be written stops the
    save before the log is written, and a log that cannot be written fails the
    save. The checkpoint runs after the reply is written. A checkpoint is
    recorded only once mined, and at the next decision if it was mined in
    between; one is in flight at a time; a reverted one is sent again; a
    recorded head is not published again; startup refuses a record beyond the
    log's length or one whose root does not match the log.

Followed by an adversarial review in a fresh context before any of it is
published.

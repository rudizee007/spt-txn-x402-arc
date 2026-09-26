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
log locator), and the settler itself refuses a missing authorization marker.
Both checks return before a key is read, and each has its own test.

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

Unknown fields are refused. `max_payments` is enforced inside the enforcement
point's policy, so a refusal for a used-up capability is a recorded DENY like
any other. It is a count of authorizations, not a spending budget. It is held in
memory and resets when the server restarts; the capability's expiry bounds that
exposure, and the operator issues a fresh capability per session. The asset is always the selected network's USDC; it
is not configurable. The recipient is carried to the enforcement point in the
transport form of §A.2 (base58 of the 32-byte widened account id).

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

**Lifetime of the signed transaction.** A signed artefact should not outlive the
authorization that produced it. An EIP-1559 transaction carries no expiry field,
so on Arc its lifetime cannot be derived from the authorization's expiry. What
bounds it instead: the signed transaction exists only in memory, is broadcast at once, and
binds a nonce that the payer's next transaction consumes. The residual is stated
here, not hidden: an endpoint that receives the signed transaction and withholds
it can submit it later, until that nonce is used. The gateway reports a
transaction that is broadcast but unconfirmed within its timeout as
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

**When.** After every N appended decisions (default 10) and on clean shutdown,
never more than once per head. A failed checkpoint is logged to stderr and
retried at the next trigger; it never blocks a decision, because a checkpoint is
evidence publication, not authorization.

**Key.** Its own key file, separate from the payment key and from the log
signing key (three keys, three roles). It holds only enough USDC for gas.

## 6. Log persistence

The log signing key and the log itself are files. The log is saved after every
append, before the tool-call returns; if the save fails, the call returns an
error and settlement does not run. On restart the log is loaded and verified
(`translog.LoadLog`) before the server accepts a call.

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
   one byte, a USDC transfer's calldata, and a payment key (I6).
7. A log save failure prevents settlement (§6).
8. Startup refuses a missing or malformed capability, unknown fields, a mainnet
   capability without explicit keys, and a checkpoint key equal to the payment
   key.

Followed by an adversarial review in a fresh context before any of it is
published.

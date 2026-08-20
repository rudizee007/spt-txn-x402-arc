# SPEC — Addendum A: Arc / EVM settlement profile (M1-Arc)

Status: draft, spec-first. Written before the code, per the repository's
trust-boundary rule.

This extends the base x402 spec, which lives in the Solana settlement
repository: [`docs/SPEC-X402.md`](https://github.com/rudizee007/spt-txn-x402-solana/blob/main/docs/SPEC-X402.md). **Read that
first** — §4 (the intent binding) and §5 (fail-closed classes) are assumed here
and not restated. Section numbers below are prefixed `A.` so they never collide
with it.

Nothing in this addendum changes the intent binding of §4. It adds a second
**settlement** path behind the same gate: the §6.4 pre-send assertion, which
today speaks SPL `TransferChecked`, gains an EVM sibling defined in §A.4.

---

## A.0 Scope and non-goals

**In scope.** Authorizing and settling a USDC payment on Arc testnet through the
existing gate, with a pre-sign guard that refuses to sign anything other than
exactly the payment that was authorized.

**Out of scope, deliberately.**

- Circle Gateway, CCTP, Circle Wallets, Circle Mint. USDC (the asset) and Arc
  (the chain) are used as *substrate*. The gate takes no dependency on any
  value-movement service; introducing one would contradict the chain-agnostic
  positioning that is the point of the component.
- The on-chain ZK verifier and ERC-3643 contracts (M2).
- Anchoring the receipt Merkle root on Arc (optional; not required for M1-Arc).
- EIP-55 checksum validation (see §A.2).
- `approve` / `transferFrom`, permit, Permit2 (see §A.5.6).

**Disclosure guardrail.** As §8 of the base spec: everything here derives from
public x402, the published SPT-Txn layer, and public Arc/EVM documentation. No
unpublished material, in code, comments, commit messages, or tests.

---

## A.1 Network profile

| Item | Value | Source |
|---|---|---|
| CAIP-2 network id | `eip155:5042002` | chain id below |
| Chain id | `5042002` | Arc docs; corroborated by chainid.network |
| RPC (HTTP) | `https://rpc.testnet.arc.io` | Arc docs |
| Explorer | `https://testnet.arcscan.app` | Arc docs |
| Faucet | `https://faucet.circle.com` | Arc docs |
| USDC ERC-20 | `0x3600000000000000000000000000000000000000` | Arc docs |
| Bound amount unit | micro-USDC, 6 decimals | ERC-20 view |

> **RPC hostname is unsettled in public sources.** Circle's own `use-arc` skill
> publishes `rpc.testnet.arc.network`; `docs.arc.io` publishes
> `rpc.testnet.arc.io`. The implementation therefore takes the RPC endpoint as
> configuration with no silent default fallback, and reports which endpoint it
> used. Confirm the live one before recording anything.

**Allowlist tag.** §4 requires `network` to be an allowlisted `u8` enum, not a
hashed string, and tags to be permanent once assigned. This profile uses
`eip155:5042002 → 3`. *(Note for the maintainer: the Solana repository is
already inconsistent — `cmd/escrowdevnet` and `escrow/link_test.go` assign
`solana:devnet → 1` while `cmd/gateway`, `cmd/mcp-*` and `demo` assign it `2`.
Tags are per-deployment configuration so nothing is presently broken, but two
values for one network in one deployment is exactly the confusable state §4 sets
out to remove. Out of scope here; flagged there.)*

**The one Arc fact that drives this entire addendum.** On Arc, USDC is the
*native gas asset* and *also* an ERC-20 at the address above. These are not two
tokens. They are one pool of funds exposed through two interfaces with two
different scales: an 18-decimal native view used by `msg.value` and gas, and a
6-decimal ERC-20 view used by `transfer` and `balanceOf`. Every threat unique to
this profile (§A.5) traces back to that sentence.

---

## A.2 Account identifiers in the binding

§4 binds `asset` and `payTo` as 32-byte values decoded from base58. An EVM
address is 20 bytes. The binding layout is published and must not change, so the
20-byte address is widened at the profile boundary:

```
accountid32 = 0x00 × 12  ‖  address20        (left-pad, big-endian)
transport   = base58(accountid32)            (the string carried in PaymentRequirements)
```

**Why this is safe.** `network_tag` is already inside the binding preimage, so a
padded EVM address under `eip155:5042002` and a Solana pubkey under
`solana:devnet` land in different preimages even if the 32 bytes were identical.
The widening adds no new collision class.

**Normative requirements.**

1. The padding is exactly 12 leading zero bytes. A decode that finds any
   non-zero byte in `accountid32[0:12]` is a hard error, never a truncation.
   Widen and narrow are one codec, round-trip tested both directions.
2. Hex parsing accepts `0x` + 40 hex digits, case-insensitive. **EIP-55 checksum
   is not validated in the guard package**: EIP-55 needs Keccak-256, which is not
   in the Go standard library, and this package takes no third-party dependency.
   What is bound is bytes, not the string, so a checksum is a typo control rather
   than a security control here. State it rather than imply it.
3. Mixed-case input is accepted and lower-cased before decoding. It is *not*
   treated as a checksummed address.

4. The narrowing is not optional at the package boundary. A bound payment is
   constructed only from 32-byte identifiers, through one constructor that
   performs the narrowing and its rejections. There is no literal form of a
   bound payment, so "take the low 20 bytes by hand and never touch the codec"
   is not a path a caller can take.

**Named wart, with the fix.** The clean design is a network-scoped address codec
inside the PEP, so `eip155:*` decodes `0x…` directly and the demo displays real
Arc addresses instead of base58 of a padded word. That is a change to the
published trust boundary of `spt-txn-pep` and carries the full review loop; it is
deliberately not attempted in M1-Arc. Recorded here so the next reader does not
mistake the workaround for the design.

---

## A.3 The transaction an ALLOW produces

An EIP-1559 (type 2) transaction:

| Field | Value |
|---|---|
| `type` | `2` — and nothing else (see below) |
| `chainId` | `5042002` |
| `nonce` | the bound nonce |
| `to` | the bound asset — the USDC ERC-20 contract |
| `value` | `0` |
| `data` | `0xa9059cbb ‖ pad12 ‖ payTo(20) ‖ amount(uint256 BE)` — exactly 68 bytes |
| `gasLimit × maxFeePerGas` | ≤ the bound fee ceiling |
| access list, authorization list, blob hashes | empty |
| signer | the authorized payer |

**The type is bound, and so is everything the type does not have.** A
transaction is an open structure. Type 3 carries blob commitments; type 4
(EIP-7702) carries an authorization list that installs code at the *signer's own
EOA*. A guard that models `to`, `value` and `data` and says nothing about the
type will certify "exactly the bound payment and nothing else" for a payload
that pays the bound 1 USDC **and** hands an attacker permanent control of the
payer's account — the standing-authority failure this project exists to remove,
granted by a transaction the guard approved. Fields outside the model are
permitted by omission unless the model forbids them, so this profile pins the
type and refuses every list the envelope can carry.

**The nonce is bound, and the value bound to it is checked.** The pre-sign
assertion is a pure function; nothing stops a compromised builder calling it
twice with two nonces and settling the bound payment twice from one
authorization. Binding the nonce makes one authorization correspond to exactly
one transaction. This is settlement-side single-use, and it composes with — it
does not replace — the gate's nonce spend-log (base spec §5), which is what
stops the *token* being replayed in the first place.

The nonce is also the **only** bound field that comes off the wire, so binding
it naively would make assertion 4 compare an endpoint-chosen value against
itself. An endpoint that returns *confirmed + 40* would obtain a valid, signed,
unexpired payment it can cause to execute whenever it later fills the gap —
handing away precisely the short-lived authority the token model exists to keep.
The settlement path therefore reads both the pending and the confirmed count and
refuses any gap between them.

**The fee ceiling is expressed in micro-USDC and converted by a ratio that is
CHECKED, not assumed.** §A.5.11 forbids converting between the 6- and
18-decimal views; a ceiling in the operator's own unit is a deliberate, narrow
exception, and it is only safe because the settlement path verifies the 10¹²
ratio against the chain at run time — the native and ERC-20 balances of the same
account are two views of one pool, so they must differ by exactly that factor.
An unchecked constant would silently multiply the ceiling by a trillion if the
assumption were wrong, disabling assertion 7 while still printing PASS. That is
the same treatment the transfer selector gets, for the same reason: a constant
nobody checks is not a constant, it is a guess.

**Gas is bounded, not unbound — because on Arc gas is the payment asset.** The
Solana profile leaves `extra.feePayer` unbound because the fee payer sponsors a
*different* resource and cannot change the payer→payTo transfer. That reasoning
does not carry over. On Arc the fee is paid in USDC out of the same pool the
payment moves, so an unbounded fee is an unbounded second payment: a perfectly
bound `transfer(payTo, 1_000_000)` alongside `gasLimit 60000 × maxFeePerGas
1e16` certifies a 1.00 USDC payment while ~600 USDC of the same funds leaves the
account. Collusion with a proposer is needed to *capture* it, but not to *burn*
it. The binding therefore carries an explicit ceiling on `gasLimit ×
maxFeePerGas`, asserted in the guard rather than in a command — a control that
lives in the settlement command is a control the guard cannot promise.

`0xa9059cbb` is the well-known ERC-20 `transfer(address,uint256)` selector. The
guard package hardcodes it because it cannot compute Keccak-256 without a
dependency; the settlement command, which already links an audited Keccak,
recomputes it at start-up and refuses to run if it disagrees. A hardcoded
constant that is differentially checked against an audited implementation is
acceptable; a hardcoded constant that nothing checks is not.

---

## A.4 The EVM pre-sign assertion (normative)

The §6.4 analogue. The guard copies the transaction, asserts against the copy,
and returns that copy as proof — so the thing that was checked is the thing that
is recorded, and a caller cannot move the bytes after the verdict. Any failure
means **do not sign**: abort, no broadcast, `DENY_VIOLATION`.

| # | Assertion | Stops |
|---|---|---|
| 1 | `type == 2` | blob and EIP-7702 payloads riding along with a bound payment |
| 2 | access list, authorization list and blob hashes are all empty | anything the envelope carries that the model does not name |
| 3 | `chainId == bound chainId` | cross-chain replay / wrong-network settlement |
| 4 | `nonce == bound nonce` | a second settlement from one authorization |
| 5 | `to != nil && to == bound asset` | proxy, router or multicall indirection; contract creation |
| 6 | `value == 0` | native-USDC smuggling alongside a clean ERC-20 payload |
| 7 | `gasLimit × maxFeePerGas ≤ bound ceiling` | an unbounded second payment in the same asset |
| 8 | `signer == bound payer`, and is not the zero address | paying from the wrong account's authority |
| 9 | `len(data) == 68` exactly | appended calldata tail consumed by a fallback |
| 10 | `data[0:4] == 0xa9059cbb` and `data[4:16]` all zero | `approve`, `transferFrom`; dirty address word |
| 11 | `data[16:36] == bound payTo` | payment redirection |
| 12 | `uint256(data[36:68]) == bound amount` | inflation and truncation |

Preconditions on the binding itself, checked at construction: identifiers narrow
cleanly from 32 bytes, no account is the zero address, the amount is non-nil,
non-negative and ≤ 2¹²⁸−1 (the binding's `u128` width), the fee ceiling is
non-nil and non-negative. A binding outside those bounds corresponds to no
representable payment and is refused rather than clamped.

**Chain id is a `uint64`, not a pointer.** Two pointer fields compared with each
other can be the *same* pointer, and `tx.ChainID = bound.ChainID` is exactly what
a builder writing "build the transaction for the bound chain" produces — it
compiles, it reads correctly, and it deletes assertion 3. A value type cannot
alias. EIP-2294 caps chain ids below 2⁶⁴, so nothing is lost.

**Unset is not zero.** `Address` is a value type, so an omitted field is
`0x00…00` rather than nil. Without an explicit rejection, forgetting to set both
the payer and the signer makes assertion 8 a `0x0 == 0x0` no-op — and both
omissions are the natural ones, because those are the two fields that do not
come from the calldata. The zero address is never a legitimate ERC-20 contract,
recipient or signer, so every account position refuses it.

**There is no "exactly one transfer" rule** analogous to the Solana
`FindTransfer` (`settle/transferchecked.go` in the Solana repository), because
an EVM transaction has exactly one top-level call. The
EVM way to hide a second transfer is a batching entry point, and assertions 5, 9
and 10 forbid it structurally.

**Pin the signer before the guard runs.** go-ethereum hashes the *signer's*
chain id into the signing preimage and overwrites the transaction's own
`chainId` field with it, so assertion 3 by itself does not decide what enters
the signature. Constructing the signer first, and asserting its chain id equals
the bound one, means the assertion and the preimage cannot drift apart. Without
that, the ordinary idiom `LatestSignerForChainID(chainIdFromRPC)` would leave
the pre-sign guard passing on a hostile chain — caught only on the post-sign leg,
after a valid signature for the wrong chain already exists in memory.

**Post-sign re-check (normative).** After signing and before broadcast, read
every field back from the signed transaction object, recover the sender from the
signature, and assert the result is field-for-field identical to what was
verified. This closes the one window the pre-sign check cannot see: a builder
that rebuilds, a signer that selects a different key, or a field mirrored
wrongly into the guard's view. The verdict carries the checked copy precisely so
this comparison has something trustworthy to compare against.

**Residual, stated.** The guard inspects a resolved view of the transaction, not
the canonical signing preimage. A field that a future EVM upgrade adds to the
type-2 envelope would be invisible to it. Assertion 1 bounds that exposure to
changes in type 2 itself; the stronger form — reconstruct the signing preimage
from the binding and compare bytes — needs an RLP implementation, and
hand-rolling a canonicalization is an automatic reject in this repository. The
post-sign re-check against the real transaction object is the practical
mitigation.

---

## A.5 Threats specific to this profile

Ordered by what would actually cost money.

**A.5.1 Native / ERC-20 dual representation — the profile's headline risk.**
A transaction can carry a perfectly bound `transfer(payTo, 1_000_000)` in its
calldata *and* a non-zero `value` moving a much larger amount of the very same
USDC natively. A guard that inspects only calldata authorizes 1 USDC and signs
away an arbitrary balance. This has no Solana analogue — SPL has no `msg.value`.
Mitigation: assertion 6, `value == 0`, non-negotiable and property-tested.

**A.5.2 Authorization by omission (EIP-7702 and friends).** The transaction
fields the guard does not model are the fields it permits. A type-4 transaction
whose call is the bound transfer and whose authorization list installs attacker
code at the payer's EOA passes every `to`/`value`/`data` check ever written.
Mitigation: assertions 1 and 2 — pin the type, refuse every list.

**A.5.3 Gas as a second payment.** Fees are denominated in the payment asset.
Mitigation: assertion 7, a ceiling inside the binding.

**A.5.4 Cross-chain replay.** A signature over a transaction whose `chainId` is
not the bound network is valid on whatever chain it does name, wherever the
payer has funds and the address holds a contract. EIP-155 prevents *accidental*
replay of a well-formed transaction; assertion 3 prevents *constructing* a
badly-formed one under a bound decision, which is the guard's job.

**A.5.5 Two settlements, one authorization.** Mitigation: assertion 4, plus the
gate's nonce spend-log upstream.

**A.5.6 Multicall / proxy indirection.** `to` set to a router or to Arc's
published `Multicall3From`, with the bound transfer as one inner call among
several. Mitigation: assertions 5, 9, 10.

**A.5.7 Calldata tail.** Solidity's ABI decoder ignores trailing calldata. A
guard written with `len(data) >= 68` accepts a payload with an appended tail that
a fallback or a non-standard token contract may act on. Mitigation: exact length,
asserted both in the guard and in the decoder so loosening one does not silently
loosen the other.

**A.5.8 Dirty address word.** The ABI decoder ignores the high 12 bytes of an
address argument, so calldata that differs from what was reviewed decodes
identically. Mitigation: assertion 10 — bind the bytes, not the decoded meaning.

**A.5.9 Standing allowance.** `approve` grants authority that persists after the
transaction — ambient authority under another name. M1-Arc never authorizes it:
assertion 10 refuses any selector but `transfer`. A future profile that needs
`approve` needs its own binding and its own review, not an added case here.

**A.5.10 A stale verdict.** The guard returns; the caller mutates the
`*big.Int` or extends the calldata slice in place; the transaction that gets
signed is not the one that was checked. Mitigation: the verdict carries a deep
copy, and the post-sign re-check compares against it.

**A.5.11 Decimal confusion.** 6 vs 18 for one asset. The bound amount is
*always* micro-USDC. Gas is *always* the native 18-decimal view. The settlement
path converts between them in exactly one place — the fee ceiling, which is a
bound, not a payment — and that conversion's ratio is verified against the
chain on every run (§A.3). No value amount is ever converted.

**A.5.12 RPC as an oracle.** Chain id, nonce, gas price and balance come from an
RPC endpoint the operator does not control. None of them may relax an assertion:
the bound `chainId` is configuration, never `eth_chainId`. An RPC that reports a
chain id other than the bound one is a mismatch to be surfaced and refused, not
a value to adopt. The nonce is read from the RPC and then *bound*, so a nonce
the RPC later changes its mind about produces a divergence rather than a second
payment — and a pending/confirmed gap at bind time is refused outright (§A.3),
which is what stops the endpoint choosing *when* the payment executes.

---

## A.6 Fail-closed classes

Unchanged from §5, applied to this path:

- `DENY_VIOLATION` — any assertion in §A.4 fails; a binding that cannot be
  constructed; RPC-reported chain id ≠ bound chain id; post-sign divergence.
- `DENY_UNAVAILABLE` — RPC unreachable, nonce or fee lookup fails, balance
  unreadable, confirmation times out with no receipt.

Neither class ever produces a signature. A signature is produced only after
every assertion in §A.4 has passed, and it is never broadcast until the post-sign
re-check has passed too.

---

## A.7 Test plan (blocking)

- **Field-flip suite.** For each assertion, mutate exactly that field of an
  otherwise-valid transaction and assert the specific sentinel. One sentinel per
  control — a generic "invalid" leaves an operator unable to tell an attack from
  a bug, which is the whole point of the two DENY classes.
- **Property test — the guard never widens.** Exhaustive over all 2¹⁵ subsets of
  the bound dimensions, with randomized corruption values and randomized
  application order: the guard returns nil **iff** no dimension was corrupted.
  The oracle is "did we corrupt anything", which is independent of the guard's
  field-by-field logic, so the test cannot pass by restating the implementation.
- **Staleness test.** Verify, then mutate the caller's `*big.Int` and extend the
  calldata slice in place (with spare capacity, so the backing array is shared),
  and assert the verdict's copy did not move and the re-check now diverges.
- **Post-sign re-check suite.** One case per field, including the recovered
  sender.
- **Constructor rejection suite.** Dirty identifier in each position, zero
  address in each position, amount out of range, missing fee ceiling.
- **Address codec round trip**, including rejection of every non-zero byte
  position in the high 12, and rejection of wrong-length input.
- **Calldata fuzz.** Random and truncated calldata into the decoder: no panic,
  and a successful decode must re-encode to the identical bytes.
- **Guard fuzz.** Random envelope, chain, nonce, gas, value and calldata: a nil
  verdict must imply exactly the bound transfer.
- **Selector differential.** The settlement command recomputes the selector with
  an audited Keccak and compares against the package constant at start-up.
- **Offline self-test in the settlement command.** `-selftest` builds every
  adversarial transaction the command can build, drives each through the real
  go-ethereum transaction object, and asserts each is refused by *its own*
  sentinel — including one post-sign mode that signs with an unauthorized
  ephemeral key, which the pre-sign guard cannot see by construction. It uses no
  key file, no RPC and no funds, so the controls can be watched firing before
  anything is spent. A mode refused by the wrong control is a failure: it would
  make the demo tell the audience the wrong story.
- **Default build stays dependency-free.** `go build ./...` and
  `go test ./...` exercise the guard without linking any chain SDK. Nothing
  under `-tags arc` may leak into them.
- **cgo build refuses.** CI asserts `CGO_ENABLED=1 go build -tags arc` FAILS. A
  deliberate compile error that nobody checks for is a compile error somebody
  deletes.

---

## A.8 Build order

1. `settle/evm/` — address codec, calldata decoder, bound-payment constructor,
   `Verify`, post-sign re-check. Pure standard library, no third-party import,
   so it compiles and tests in the default build exactly like `settle/`.
2. Tests per §A.7.
3. Adversarial review in a fresh context, hostile brief. *(Round 1, on the
   guard: found the missing transaction-type assertion, the zero-address no-op,
   the aliased chain-id pointer, the unbounded gas, and the stale verdict.
   Everything above phrased as a hard rule is there because round 1 broke the
   version without it.)*
4. `cmd/payarc` behind `-tags arc` — the only file that touches keys and the
   network, excluded from the default build, mirroring `cmd/paydevnet` in the
   Solana repository.
5. Adversarial review in a fresh context, on the settlement path. *(Round 2:
   found no way to sign an unauthorized transaction, and found the RPC-chosen
   nonce, the unverified decimal ratio, the signer-vs-preimage chain id, an
   unchecked gas-estimate overflow, two comparisons of a value against itself,
   and the untested post-sign leg. All addressed above.)*
6. Maintainer line-by-line review before anything is committed or recorded.

---

## A.9 Dependency note for the maintainer (not a spec requirement)

`cmd/payarc` needs EIP-1559 transaction encoding and secp256k1 signing. Both are
canonicalization and cryptography, so hand-rolling either is out; the practical
choice is `github.com/ethereum/go-ethereum`. That dependency and its ~26
transitive modules are the reason this profile lives in its own repository
rather than beside the Solana settler: the guard is auditable in an afternoon
precisely because the tree around it is small.

Two consequences the maintainer should decide on deliberately:

- **cgo.** go-ethereum links C `libsecp256k1` when cgo is enabled, and falls
  back to the audited pure-Go `decred/dcrd/dcrec/secp256k1` when it is not.
  CLAUDE.md forbids C/C++ inside the trust boundary, including via cgo. The
  command therefore fails to build with cgo enabled, by a deliberate build-tagged
  compile error rather than by a note in a README — build it with
  `CGO_ENABLED=0`.
- **Licence.** go-ethereum's library is LGPL-3.0. This repository is Apache-2.0.
  The guard package itself takes no dependency and stays clean; only the
  build-tagged demo command links it, and it is not part of any distributed
  artifact. That is probably fine, and it is still a call for the maintainer
  rather than a detail to discover later in a procurement review. Keeping it out
  of the Solana repository, whose dependency story is "one chain SDK and the
  PEP", is part of the answer.

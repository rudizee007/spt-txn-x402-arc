# SPEC: Milestone 3 — Circle Wallets guarded signing, x402 and Gateway authorizations, CCTP, Permit2 and EURC guards

Status: REVIEWED. Owner rulings on O-1 to O-8 are recorded in §10 and applied
throughout. P1 implementation is approved against this revision. Items still
marked [V] or deferred are not. Companion to [`SPEC-X402-ARC.md`](SPEC-X402-ARC.md) (the §A.4
transaction assertions) and [`SPEC-ARC-GATE.md`](SPEC-ARC-GATE.md) (the
Milestone-2 gateway), both of which this document extends and neither of which
it changes.

Branch: `m3-circle`, from `main` at `a64d4c0`.

## 0. How to read this document

Every requirement carries one label. A label is a statement about where the
requirement comes from, not about how important it is.

| Label | Meaning | Who can change it |
|---|---|---|
| **[C]** | Submitted commitment: the Milestone-3 text as submitted, quoted or restated without widening | Nobody, short of an amended submission |
| **[D]** | Implementation design proposed here to meet a [C] | The owner, at review |
| **[V]** | An assumption about Circle, Arc or x402 that must be verified against a primary source before code depends on it | Resolved by verification, recorded in §9 |
| **[O]** | An owner decision; §10 records the ruling, or that it is deferred | The owner |
| **[X]** | Explicitly deferred: not Milestone 3 | — |

A [D] is never a submitted requirement. Where a [D] goes beyond the submitted
text, it says so.

## 1. Submitted commitments

Restated from the Milestone-3 submission. Nothing here is added to it.

**C1 — Circle Wallets.** The guard sits in front of the developer-controlled
wallet's sign-transaction call: it asserts the transaction, Circle signs without
broadcasting, and the guard recovers the sender, re-checks every field and
broadcasts only if nothing changed.

**C2 — Two controls.** Circle's wallet policy and our binding remain two
independent controls.

**C3 — Observe mode.** Observe mode lets a team run the guard beside an existing
integration and see what it would refuse before switching enforcement on; it only
reports and never approves a refused payment.

**C4 — Wallet type check.** Circle's API lists ARC but limits raw-transaction
signing to some wallet types; confirm which in week one and fall back to the
typed-data endpoint if needed.

**C5 — x402 and Gateway.** An x402 `exact` payment on EVM is a signed EIP-3009
authorization that a facilitator submits later; Gateway nanopayments are signed
authorizations too. The guard decodes the EIP-712 data before signing and refuses
unless token, chain, recipient, amount and validity window match.

**C6 — Window.** The window is derived from the authorization's own expiry, so a
signature cannot outlive its permission.

**C7 — CCTP.** `depositForBurn` with an attacker's `mintRecipient` or a wrong
`destinationDomain` is cross-chain theft with no recourse. The guard binds the
destination domain, the recipient, the amount and the burn token.

**C8 — Permit2 and EIP-2612.** A permit grants standing allowance by signature
alone, and Permit2 is required for StableFX on Arc. The guard binds signed
permits so an agent cannot grant authority it was never given.

**C9 — EURC.** The payment guard covers EURC. Authorization bound to one asset
must not authorize movement of the other.

**C10 — Deliverable.** All guards open-sourced and wired into the Milestone-2
gateway, each with an offline adversarial suite.

**C11 — Success metric.** A Circle-wallet-signed payment and an x402 payment on
Arc, each checked before signing; every refusal reproducible offline with no key
and no funds.

## 2. Architecture

```
agent ──MCP──▶ SPT-Txn MCP enforcement point      decides: is this tool-call authorized?
                   │  token verified, then removed;   (DELEGATION-INTENT-MCP §2–§3)
                   │  only an authorized call is forwarded
                   ▼
              arc-gateway (this repository)         decides: is it inside the local capability?
                   │                                  (mcpgate, unchanged from M2)
                   ▼
              rail guard (this repository)          asserts: is THIS transaction or typed
                   │                                  authorization exactly the bound one?
                   ▼
              signer (local key, or Circle Wallets) → Arc / facilitator / Circle
```

**[D] The enforcement point is a separate program.** `arc-gateway` runs as the
MCP server that an SPT-Txn MCP enforcement point wraps, for example `cmd/mcp-pep`
in `spt-txn-poc`. This repository does not import, vendor or require any
enforcement-point code. Its only contract with the enforcement point is the
public one: the agent attaches its token at `params._meta["spt-txn/token"]`, the
enforcement point verifies it against the call and removes it, and forwards only
an authorized call. This was planned in `SPEC-ARC-GATE.md` §1, and the settler
already accepts an authorized call whichever enforcement point produced it.

**[D] One target, checked.** The intent digest (§6) covers the enforcement
point's configured server identity (`target`). The gateway takes the same value
as a required setting, `-server-identity`. Startup refuses an empty value, a value
with leading or trailing whitespace, and a value containing control characters.
The value is printed at startup and recorded in every correlation record (§6.3),
so a mismatch is visible. Each payment tool also takes a required
`server_identity` argument. The gateway refuses a call whose `server_identity` is
not byte-equal to its own setting, so a call minted for an enforcement point with a
different identity fails closed at the gateway. The gateway cannot read the
enforcement point's configuration. This check therefore catches only a mismatch
that also appears in the arguments; matching the two configurations remains an
operator duty, stated in the runbook.

**[D] Build boundary.** Every guard and every adversarial suite builds and runs
from a clone of this repository alone, with public Go modules, with no network
access at test time, no real key and no funds. The guard packages stay free of
go-ethereum, as `settle/evm` is today; signing, recovery and broadcast stay in the
build-tagged `arc` commands.

### 2.1 Independent controls

Each is required to refuse on its own; removing any one must leave the others
able to refuse, and each has a failing test that shows it (extends
`SPEC-ARC-GATE.md` I3).

1. The enforcement point's decision on the tool-call and its token.
2. The gateway's capability check (recipient, asset, maximum amount, count,
   expiry).
3. The rail guard's assertion on the exact bytes to be signed, before signing,
   and again on what was signed.
4. Circle Wallets only: Circle's own wallet policy (C2). The guard never relies on
   it and never weakens because of it.

### 2.2 Invariants

These carry forward I1–I5 of `SPEC-ARC-GATE.md` and add:

- **M1 — One source [C5, C7, C8].** Every bound field (token, chain, recipient,
  amount, window, domain, spender, nonce) comes from the authorized tool-call and
  the capability, never from a second parse, a server response, a facilitator, or
  the wallet provider.
- **M2 — Construct, then compare [D].** The guard builds the expected transaction
  or EIP-712 message from the binding, computes its hash itself, and accepts a
  signature only if it recovers to the authorized signer over *that* hash. It
  never signs, or lets a provider sign, data it did not construct. This goes
  beyond the submitted text, which requires decoding before signing; constructing
  is the stricter form of the same check.
- **M3 — Recheck after signing [C1].** After any signature, the guard recovers the
  signer and re-checks every field against the binding before anything is
  broadcast or handed on.
- **M4 — Asset isolation [C9].** The asset (token contract and chain) is part of
  every binding. An authorization bound to USDC never verifies against EURC, and
  the reverse, on every rail.
- **M5 — Bounded lifetime [C6].** No signature is produced whose validity outlives
  the gateway's authorization it serves: the capability and the call (§4.1.3).
- **M8 — Separate identities [O-1, O-7].** The intent digest (authorization and
  correlation identity), the gateway's single-use nonce (gateway replay state) and
  a rail nonce such as the EIP-3009 nonce (on-chain replay state) are three
  different values. A rail nonce may be derived from the intent digest under its
  own domain tag. No value serves in two protocol roles.
- **M6 — Observe never approves [C3].** Observe mode has no code path that signs,
  broadcasts or returns an approval (§5).
- **M7 — Fail closed.** An unknown field, an unknown variant, an unparseable
  value, an unset address or an unavailable dependency is a refusal with a
  distinguishable class (violation or unavailable), never a default.

## 3. Shared design

**[D] Strict tool arguments — a trust-boundary fix.** The gateway currently
decodes tool arguments with `encoding/json` into a struct, which matches member
names case-insensitively, ignores unknown members and keeps the last of duplicate
members. The enforcement point binds the exact argument object. A call such as
`{"to":"0xA…","To":"0xB…"}` is one object to the enforcement point, while the
gateway's reading of it depends on decoder behaviour.

The fix is made in two steps, and the evidence is kept:

1. **Before the parser changes,** a discriminating test shows the disagreement on
   the unchanged code: a mis-cased duplicate of a security field (`to` / `To`,
   `amount_usdc` / `Amount_USDC`); an exact duplicate member; an unknown member; and
   an alternative representation that the enforcement point binds but the gateway
   reads differently, for example a JSON number amount where a decimal string is
   required. Each case records what the gateway currently does. The test is
   written to pass only once the parser is strict, and it fails on the unchanged
   code.
2. **The parser changes.** It requires exact member names, no duplicate members, no
   unknown members, every required member present, monetary amounts as decimal
   strings, and fails closed on any malformed or unrecognised representation. The
   same test then passes.

The commit history shows the test failing before the change and passing after.
The generic suite passing is not offered as evidence for this fix.

**[D] Canonicalization in this repository [O-5].** The gateway needs RFC 8785
(JCS) to recompute the intent digest (§6). Adding a runtime dependency on the
reference implementation only for that is not allowed, so this repository
carries a minimal JCS restricted to the subset the reference accepts: objects,
arrays, strings, `true`, `false`, `null`, and integers with |n| ≤ 2^53−1. It
refuses fractions, exponents, `-0`, larger integers, duplicate members, and
invalid UTF-8 or unpaired surrogates. It is proven byte-for-byte against the
public reference with known-answer and cross-implementation vectors. The vectors
are generated by running the reference, and their bytes are checked in, so the
test needs no dependency on it. They cover member ordering by UTF-16 code units,
string escaping (control characters, `"`, `\`, `/`, U+2028, U+2029, characters
above U+FFFF), non-ASCII text, nesting, empty containers, the integer boundaries
±(2^53−1), and every refused numeric form.

The digest invariant: compute over the arguments exactly as received, before
strict semantic decoding or defaulting, canonicalize with the proven JCS, and
never hash the received bytes.

**[D] Amounts.** Amounts are decimal strings in the tool arguments, parsed by
`spt-txn-pep/amount` as today. Integer JSON numbers above 2^53−1 and all non-integer
numbers are refused; the enforcement point's canonicalization refuses them too
(§6), so allowing them would only create a call that is denied upstream.

**[D] EIP-712 hashing [O-5].** Keccak-256 in the guards comes from
`golang.org/x/crypto/sha3` (`NewLegacyKeccak256`). The guards use no other new
dependency.

**[D] One guard package per rail**, each with: a `Binding` validated into an
unexported bound type (as `evm.NewBoundPayment`), a constructor for the expected
message or transaction, a `Verify` that returns a value only on success, and a
post-signature check.

## 4. Rails

### 4.1 x402 `exact` / EIP-3009 — priority P1

#### 4.1.1 What is signed

**[V-1]** An x402 `exact` payment on EVM is an EIP-3009
`TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)`
signed under the token's EIP-712 domain
`(string name,string version,uint256 chainId,address verifyingContract)`, with
`name` and `version` carried in the payment requirements' `extra`. To be confirmed
against the x402 specification version the facilitator implements.

**[V-2]** Arc USDC at `0x3600000000000000000000000000000000000000` exposes
`transferWithAuthorization`, `receiveWithAuthorization`, `cancelAuthorization`,
`authorizationState`, `permit`, `nonces`, `DOMAIN_SEPARATOR` and `version`.
Source: the `NativeFiatTokenV2_2` ABI shipped in `circlefin/arc-node`
(`assets/artifacts/stablecoin-contracts/`, commit `6e76402`). The domain `name`
and `version` must be read from each network and pinned in configuration; they
are never adopted at run time from a payment requirement.

#### 4.1.2 Assertions [C5, D]

The guard refuses unless every one of these holds:

1. the domain's `verifyingContract` equals the bound asset contract, and the asset
   is the one the capability names (USDC, or EURC under §4.6);
2. the domain's `chainId` equals the bound chain, and `name` and `version` equal
   the pinned values for that contract and chain;
3. the primary type is exactly `TransferWithAuthorization` ([O-2]: the only
   variant in M3, subject to V-1);
4. `from` equals the authorized payer, and is not the zero address;
5. `to` equals the bound recipient;
6. `value` equals the bound amount exactly;
7. the window holds (§4.1.3);
8. `nonce` equals the nonce the guard derives (§4.1.4), and nothing else;
9. after signing, the signature recovers to `from` over the guard-computed digest
   (M2, M3), and its `s` value is in the lower half of the curve order.

#### 4.1.3 Validity window [C6, O-3]

```
validAfter  ≤ now at signing
validBefore ≤ min(capability expiry, call expiry, now + max authorization lifetime)
validBefore > validAfter
```

The capability expiry and the call expiry are the ones the gateway already
enforces (`SPEC-ARC-GATE.md` I5). The maximum authorization lifetime is a
required setting, and startup refuses zero or negative values. "The
authorization's own expiry" in C6 therefore means, in M3, the expiry of the
gateway's authorization: the capability and the call.

What this does not claim: the enforcement point removes the token before the call
reaches the gateway, so the gateway does not know the token's expiry. An argument
the intent digest authenticates (for example a `valid_before`) proves only that
the token's issuer bound that value. It does not prove the value is no later than
the token's own expiry. This specification therefore does not treat any argument
as the token's expiry. If an authenticated, enforced relationship
`valid_before ≤ token expiry` is established later, §4.1.3 may be tightened to use
it (§11).

#### 4.1.4 Nonce [O-1]

EIP-3009 nonces are 32 bytes chosen by the signer. On-chain, `authorizationState`
makes a nonce usable once. Before submission, anyone holding a signed
`transferWithAuthorization` can submit it, to the bound recipient only.

The guard derives the nonce itself:

```
raw_intent_digest = base64url-decode(intent_digest)          ; exactly 32 bytes (§6)
eip3009_nonce     = SHA-256( "spt-txn-eip3009-nonce-v1" || 0x00 || raw_intent_digest )
```

- The tag is the 24 ASCII bytes `spt-txn-eip3009-nonce-v1`, with no length
  prefix and no terminator other than the single `0x00` that follows it. The input
  is exactly 32 bytes, so the preimage is always 57 bytes.
- `intent_digest` must decode, as unpadded base64url, to exactly 32 bytes.
  Anything else is a refusal. Padded, standard-alphabet or non-canonical
  encodings are refused, not normalized.
- The 32-byte output is the EIP-3009 `bytes32 nonce`, in the byte order SHA-256
  produces it.
- The guard refuses an authorization carrying any other nonce.
- Known-answer vectors lock the encoding: at least an all-zero digest, an all-0xFF
  digest and one random digest, each with its base64url form and resulting nonce.

`payment_id` is mandatory and makes each payment's intent unique (§6.2). The
nonce is therefore unique per payment, and a second settlement of the same
authorized call is refused on-chain by `authorizationState`.

The chain this gives: enforcement point `intent_digest` → domain-separated
EIP-3009 nonce → signed authorization → on-chain authorization state. The digest
itself never appears as the nonce (M8).

### 4.2 Circle Wallets guarded signing — priority P1

#### 4.2.1 Flow [C1, D]

1. Build the EIP-1559 transaction from the binding, as `cmd/payarc` does now.
2. Pre-sign: `evm.Verify` (the twelve §A.4 assertions, unchanged). Then write and
   sync the correlation record (§6.3, rail `0x02`, `guarded_id` = the EIP-1559
   signing hash).
3. Serialize the unsigned transaction and send it to the developer-controlled
   wallet's sign-transaction call. Circle signs and does not broadcast.
4. Decode the returned signed transaction. Recover the sender and re-run the
   assertions on the decoded transaction. Require the recovered sender to equal the
   bound payer, and every field to be identical to step 1 (`Verified.AssertSame`).
   Require the returned transaction hash to equal the hash computed locally.
5. Broadcast the guard-checked bytes through the gateway's own RPC connection
   only if step 4 passed. A provider-side broadcast is never relied on.

**[V-3]** The developer-controlled wallets SDK exposes `signTransaction({walletId,
rawTransaction})`. For EVM it takes hex, returns `signature`,
`signedTransaction` and `txHash`, and does not broadcast. The `ARC` and
`ARC-TESTNET` blockchain identifiers are used for signing calls. Source: Circle's
public agent-skill references (`circlefin/skills`, commit `58ab864`,
`use-developer-controlled-wallets/references/sign-with-wallet.md`). This is a
secondary source and must be confirmed against the API reference.

**[V-4] — the C4 week-one check.** Which account types (EOA or SCA) may call
sign-transaction on `ARC` / `ARC-TESTNET`. The public sources reached so far do
not state it. An SCA is an ERC-4337 contract account and does not produce a raw
EOA transaction signature, so EOA is the expected answer. **If** sign-transaction
is not available for the wallet type used, C4's fallback applies: the payment is
made as an EIP-3009 authorization signed through `signTypedData`, and §4.1 guards
it.

**[D] Entity secret and API key.** These are read from owner-only files, checked
the same way as the M2 key paths, and never logged. They exist only in the
build-tagged command, never in a guard package or a test.

#### 4.2.2 Circle's wallet policy [C2]

The guard does not read, configure or depend on Circle's wallet policy. A policy
refusal is reported as the provider's refusal. A policy approval adds nothing to
the guard's decision. A test runs the guard against a simulated provider that
signs anything and shows the guard still refuses.

### 4.3 Circle Gateway authorizations — priority P2

**[V-5]** A Gateway transfer is authorized by an EIP-712 `BurnIntent` (or
`BurnIntentSet`) containing a `TransferSpec`: `version, sourceDomain,
destinationDomain, sourceContract, destinationContract, sourceToken,
destinationToken, sourceDepositor, destinationRecipient, sourceSigner,
destinationCaller, value, salt, hookData`, plus `maxBlockHeight` and `maxFee`.
Source: `circlefin/evm-gateway-contracts`, `src/lib/BurnIntents.sol`, commit
`c21d2d2`.

**[V-6]** The Gateway EIP-712 domain is `EIP712Domain(string name,string version)`
with `name = "GatewayWallet"` and `version = "1"`. It has **no `chainId` and no
`verifyingContract`** (`src/lib/EIP712Domain.sol`, same commit). Chain and contract
binding must therefore come from the `TransferSpec` fields: domains, contracts and
tokens. The guard cannot rely on the domain for them.

**[V-7]** "Gateway nanopayments" (C5): the exact signed message used by Circle's
nanopayment flow (Circle's `x402-batching` path) has not been confirmed from a
primary source. Until it is, the guard targets the `BurnIntent` format above, and
the nanopayment format is verified before code depends on it.

**[O-4] — deferred.** C6 requires a window derived from expiry. `BurnIntent`
carries `maxBlockHeight`, a block height rather than a time. No rule relating time
to block height is set until V-5, V-7 and the actual Gateway and nanopayment
signed formats are verified. Until then the Gateway guard is not implemented.

[D] Once that evidence exists, the guard binds: source and destination domain,
source and destination contract, source and destination token, depositor,
recipient, signer, value, `maxFee ≤` bound, `hookData` empty unless bound,
`destinationCaller` per capability, and a window rule decided under [O-4]. A `BurnIntentSet` is refused unless every
member is bound.

### 4.4 CCTP — priority P2

**[V-8]** CCTP V2 `TokenMessengerV2.depositForBurn(uint256 amount, uint32
destinationDomain, bytes32 mintRecipient, address burnToken, bytes32
destinationCaller, uint256 maxFee, uint32 minFinalityThreshold)`, with
`depositForBurnWithHook` as a separate entry point
(`circlefin/evm-cctp-contracts`, `src/v2/TokenMessengerV2.sol`, commit `a92a2b4`).
Arc's CCTP domain is `26` ([V-9]). Which TokenMessenger version and address Arc
uses must be confirmed.

[C7] The guard binds the destination domain, `mintRecipient`, the amount and the
burn token.

[D] Beyond C7, so that the four bound fields cannot be undermined by the other
three:

- `maxFee` ≤ a bound in the capability. The fee is taken from the burned amount, so
  an unbounded `maxFee` is a loss not covered by binding `amount`;
- `destinationCaller` equals the bound value (zero if unbound);
- `minFinalityThreshold` is one of the bound values;
- `depositForBurnWithHook` and the V1 entry points are refused unless explicitly
  bound;
- the transaction-level §A.4 assertions still apply (type 2, value 0, the bound
  `to`, exact calldata length, the fee ceiling), with the TokenMessenger contract
  as `to`;
- for an EVM destination, `mintRecipient` must have clean high 12 bytes, as the M1
  address codec requires.

### 4.5 Permit2 and EIP-2612 — priority P2

**[V-10]** Permit2 is at the canonical address
`0x000000000022D473030F116dDEE9F6B43aC78BA3` in the Arc mainnet and testnet
genesis (`circlefin/arc-node`, `assets/{mainnet,testnet}/genesis.json`, commit
`6e76402`). C8's "required for StableFX on Arc" is taken from the submission; the
StableFX integration's exact Permit2 call (allowance or signature-transfer, single
or batch, witness type) is to be verified.

[C8] The guard binds signed permits so an agent cannot grant authority it was
never given.

[D] EIP-2612 `Permit(owner, spender, value, nonce, deadline)`: bind the token
domain (as §4.1.2 items 1–2), `owner` = payer, `spender` = the bound spender,
`value` ≤ the bound amount, `nonce` = the token's current nonce for the owner,
`deadline` per §4.1.3.

[D] Permit2: accept only the variants the capability names. For each, bind token,
amount, spender, nonce and expiration or deadline. Refuse the maximum-value
allowance sentinels (`2^160−1` for an allowance amount, `2^256−1` for a value)
unless explicitly bound. Refuse batch variants unless every element is bound.
Refuse a witness type that is not bound.

### 4.6 EURC — priority P2

**[V-11]** EURC on Arc (6 decimals): mainnet
`0xbEf5f6d51CB62b58e6A8f77868681825C6fe21c1`, testnet
`0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a`. Source: `circlefin/skills`
(`use-arc/SKILL.md`, commit `58ab864`), a secondary source, to be confirmed
against Arc's published contract addresses and on-chain.

[C9] Every guard covers EURC.

[D] The capability names exactly one asset. EURC is an ordinary ERC-20 and not the
gas asset, so the native-value assertion (§A.4 #6) still requires `value == 0` and
the fee ceiling is still in USDC. For every rail, an adversarial test presents a
USDC-bound authorization against EURC and the reverse, and both are refused. The
amount parser is shared (`spt-txn-pep/amount`, 6 decimals). [V-12]: EURC's
EIP-712 `name` and `version`, and whether it implements EIP-3009 and EIP-2612 on
Arc.

## 5. Gateway integration and modes [C3, C10]

The M2 modes (live, dry-run, evaluate-only; `SPEC-ARC-GATE.md` §6a) are unchanged.
M3 adds the rail as a startup setting (one rail per process, as one capability per
process today) and adds observe mode.

**[D] Observe mode.**

- Input: the transaction or typed data an existing integration is about to sign,
  plus the binding it claims to serve.
- Output: the guard's verdict and the reason, recorded in a log of its own
  ([O-6]).
- Observe mode holds no payment key and no wallet credential. It returns nothing a
  signer can use, and has no path to sign or broadcast. A refusal is reported as
  "would refuse". An acceptance is reported as "would accept", never as an
  approval.
- It cannot be combined with live mode in one process.

**[O-6] Separate log per mode.** The M2 log records the decision, not the mode
(`SPEC-ARC-GATE.md` §6a residuals). Observe mode writes to its own log file, with
its own correlation file. The gateway's state record for a log names the mode
that created it, and startup refuses a log whose state names another mode. `spt-txn-pep/translog` is not changed.

## 6. Correlating the enforcement point's receipt with the gateway's decision

**Question.** Can the gateway compute, from the authorized call it receives, a
value that provably equals the intent digest in the enforcement point's receipt?

**What the public specification and reference implementation define.**
`DELEGATION-INTENT-MCP.md` §2 and `internal/intent` in `spt-txn-poc`:

```
intent_digest = base64url( SHA-256( "spt-txn-intent-v1" || 0x00 ||
                  JCS({ "tool": <tools/call name>,
                        "params": <tools/call arguments, absent → {}>,
                        "target": <the enforcement point's configured server identity> }) ) )
```

JCS here is the RFC 8785 subset of `spt-txn-poc/pkg/jcs`: integers up to 2^53−1
only, no other numbers. In the reference enforcement point, a PERMIT receipt's
`intent_digest` is the digest bound in the token, and the engine has already
compared it in constant time with the digest recomputed from the forwarded call.

**Measured.** In the reference `cmd/mcp-pep`, the forwarded request is
re-encoded: `params` is rebuilt with `encoding/json`, which removes whitespace and
escapes `<`, `>`, `&`, U+2028 and U+2029. A differential test against the
reference code (five argument objects: plain; whitespace and HTML characters;
non-ASCII and U+2028; nested arrays and objects; non-integer numbers) found:

- the bytes of `arguments` change in two of the four accepted cases;
- the recomputed intent digest is equal in all four accepted cases;
- the object with non-integer numbers is refused by the canonicalizer, so such a
  call is denied before it is forwarded.

### 6.1 Conclusion

The formats already allow correlation, with no change to the enforcement point.
The gateway can recompute the digest if:

1. it is configured with the same `target` string as the enforcement point, and
   checks it as §2 describes;
2. it canonicalizes with the JCS in this repository, proven byte-identical to the
   reference (§3, [O-5]). It never hashes the received bytes;
3. it computes over the arguments exactly as received, before strict decoding
   (§3) and before any defaulting.

### 6.2 Uniqueness

Two identical authorized calls have the same digest. The digest identifies one
payment only if the arguments are unique per payment. [D] Every payment tool takes
a required `payment_id`: exactly 64 lowercase hexadecimal characters (32 bytes),
chosen by the caller. The gateway refuses a `payment_id` it has already
recorded, using the correlation file (§6.3) as the record.

### 6.3 Recording: a side correlation record [O-7]

The intent digest, the gateway nonce and a rail nonce stay separate values (M8).
The gateway keeps its existing random single-use nonce, and the log
(`translog.Record`) is not changed. The correlation is written to a separate,
append-only file next to the log.

**Record.** One record per decision that reaches a rail guard, in a fixed-width,
domain-separated encoding (no JSON, so there is nothing to canonicalize):

| Field | Size | Content |
|---|---|---|
| tag | 27 | ASCII `spt-txn-arc-correlation-v1`, then `0x00` |
| layout | 1 | `0x01` |
| seq | 8 | correlation record index, little-endian, from 0 |
| log_seq | 8 | `Seq` of the log record it refers to |
| log_record_hash | 32 | `Record.Hash()` of that log record |
| intent_digest | 32 | raw intent digest (§6) |
| payment_id | 32 | raw `payment_id` |
| target_hash | 32 | SHA-256 of the configured server identity |
| rail | 1 | `0x01` EIP-3009, `0x02` Circle Wallets transaction (further values per rail) |
| guarded_id | 32 | EIP-3009: the EIP-712 digest that is signed. Transaction: the EIP-1559 signing hash |
| prev_hash | 32 | SHA-256 of the previous record's encoding, or 32 zero bytes for the first |

Each record is followed by an Ed25519 signature over its encoding, made with the
existing log signing key. The key is not used for any other message with this
tag, and the tag and layout byte keep these messages apart from log entries.

**Integrity relationship.**
- `log_record_hash` ties each record to one log entry. That entry is in the
  signed, hash-chained log, and its Merkle root is checkpointed on Arc (M2). A
  correlation record cannot be moved to another decision without failing that
  check.
- `prev_hash` chains the records, and the signature authenticates each one, so a
  removed, reordered or edited record is detected by anyone holding the log
  public key.
- `guarded_id` is computed before signing, so the record can be written, and made
  durable, before the guarded artefact exists.
- For EIP-3009, the on-chain nonce is derived from `intent_digest` (§4.1.4). That
  gives a second, independent on-chain link for that rail.

**Order and failure.** The decision is persisted first (`SPEC-ARC-GATE.md` §6).
Then the correlation record is written and synced. Only then is the artefact
signed or handed on. If the record cannot be persisted, nothing is signed, and the
call is reported as unavailable.

**Residual, stated.** The correlation file is not itself checkpointed on Arc. Its
integrity rests on the log key and on its tie to checkpointed log entries.
Truncating the end of the file goes undetected unless a later record, or the
count published with the evidence, exposes it. Closing this gap would mean
anchoring the correlation head, which is not in M3 (§11).

### 6.4 Resulting chain

Enforcement-point receipt (`intent_digest`) ↔ correlation record (`intent_digest`,
`payment_id`, `log_record_hash`, `guarded_id`) ↔ gateway log entry ↔ checkpoint on
Arc (M2) ↔ the guarded transaction or authorization. Its fields are derived only
from the same arguments (M1), and for EIP-3009 its nonce is derived from the same
digest. An auditor holding the receipt, the log, the correlation file and the
chain can check every link offline.

### 6.5 Classification

No change is needed in the enforcement point, and none in `spt-txn-pep`. The
remaining work is configuration (the shared `target`) and this repository's own
implementation.

## 7. Offline adversarial suites [C10, C11]

Each rail ships a suite that runs with `go test` from a clean clone, with no
network, no real key and no funds. Keys in tests are fixed test keys generated
for the suite. Each suite contains at least:

- a mutation of every bound field, one at a time, each refused with its reason;
- the asset swap (USDC ↔ EURC) and the chain swap (testnet ↔ mainnet chain id);
- a signature by the wrong key, a signature over a different digest, and a
  malleated (high-s) signature;
- a window that outlives the authorization, a window not yet open, and an
  over-long window;
- unknown or duplicate argument members, mis-cased members, oversize and
  non-decimal amounts;
- a provider that returns a different transaction or signature from the one
  requested (Circle Wallets);
- observe mode: no input produces a signature, a broadcast or an approval;
- known-answer tests for every EIP-712 digest and every calldata encoding,
  against vectors computed with an independent implementation and checked in as
  bytes;
- known-answer and cross-implementation vectors for the JCS in this repository
  (§3) and for the EIP-3009 nonce derivation (§4.1.4);
- the strict-argument evidence (§3): the discriminating test committed failing
  on the unchanged parser, then passing on the strict one;
- the existing mutation script (`scripts/mutate-evm-guard.sh`) extended to the new
  guard packages: each assertion removed must fail a test.

C11's "every refusal reproducible offline" means: for every refusal the live
demonstration shows, the evidence directory contains the inputs, and a test or a
command reproduces the same refusal from them with no key and no network.

## 8. Order of work

Following the submitted success metric:

| Priority | Item |
|---|---|
| P1 | x402 / EIP-3009 guard (§4.1), wired into the gateway |
| P1 | Circle Wallets guarded signing (§4.2), wired into the gateway |
| P1 | Offline adversarial suites for both (§7) |
| P2 | Gateway authorization guard (§4.3) |
| P2 | Permit2 / EIP-2612 (§4.5) |
| P2 | EURC across rails (§4.6) |
| P2 | CCTP (§4.4) |
| P3 | Live evidence, documentation, README status |

## 9. Assumptions to verify

| Id | Assumption | Source so far | Status |
|---|---|---|---|
| V-1 | x402 `exact` EVM = EIP-3009 `TransferWithAuthorization`; `extra` carries `name`, `version` | x402 scheme description (to be pinned to a version) | open |
| V-2 | Arc USDC implements EIP-3009 and EIP-2612; domain values per network | `circlefin/arc-node` `6e76402` ABI | ABI confirmed; domain values open |
| V-3 | `signTransaction` for EVM: hex in; `signature`, `signedTransaction`, `txHash` out; no broadcast; `ARC`/`ARC-TESTNET` ids | `circlefin/skills` `58ab864` (secondary) | to confirm against the API reference |
| V-4 | Wallet types allowed to sign raw transactions on Arc (C4) | not stated in sources reached | **week one** |
| V-5 | Gateway `BurnIntent` / `TransferSpec` layout | `circlefin/evm-gateway-contracts` `c21d2d2` | confirmed at that commit |
| V-6 | Gateway domain has no `chainId` / `verifyingContract` | same | confirmed at that commit |
| V-7 | Nanopayment signed-message format | not confirmed | open |
| V-8 | CCTP V2 `depositForBurn` signature; contract and version on Arc | `circlefin/evm-cctp-contracts` `a92a2b4` | signature confirmed; Arc deployment open |
| V-9 | Arc CCTP domain `26` | `circlefin/skills` `58ab864` (secondary) | to confirm |
| V-10 | Permit2 canonical address on Arc; StableFX's Permit2 usage | `circlefin/arc-node` genesis `6e76402` | address confirmed; StableFX usage open |
| V-11 | EURC addresses on Arc | `circlefin/skills` `58ab864` (secondary) | to confirm on-chain |
| V-12 | EURC EIP-712 domain; EIP-3009 / EIP-2612 support on Arc | — | open |

The documentation site `developers.circle.com` was not reachable from the
environment in which this specification was written. Each "secondary" source above is
confirmed against it, or against the deployed contracts, before code depends
on it.

Note on prior material: an earlier Step-1 EIP-3009 specification with an owner
ruling on nonces is believed to have existed. It was not found in this repository's
branches or in the other material available when this specification was written.
§4.1.4 states the current owner ruling ([O-1], §10).

## 10. Owner decisions — rulings

| Id | Decision | Ruling |
|---|---|---|
| O-1 | EIP-3009 nonce | **Modified.** Nonce = SHA-256(`spt-txn-eip3009-nonce-v1` ‖ 0x00 ‖ raw intent digest), locked by known-answer vectors. The raw digest is not used as the nonce. `payment_id` is mandatory. The guard constructs the nonce and refuses any other (§4.1.4). |
| O-2 | EIP-3009 variant | **Approved.** `TransferWithAuthorization` only, subject to V-1. `receiveWithAuthorization` only if the verified x402 flow requires it. |
| O-3 | Authorization expiry | **Option (a), refined.** `validBefore ≤ min(capability expiry, call expiry, configured maximum lifetime)`. No argument is treated as the token's expiry (§4.1.3). |
| O-4 | Gateway `maxBlockHeight` window | **Deferred** until V-5, V-7 and the actual Gateway/nanopayment format are verified. No time-to-height rule before then. |
| O-5 | Keccak-256 and JCS | **Approved with refinement.** `golang.org/x/crypto/sha3` for Keccak-256. A minimal JCS in this repository, proven byte-for-byte against the public reference. No runtime dependency on the reference (§3). |
| O-6 | Observe records | **Approved.** Separate log per mode. No `translog` change (§5). |
| O-7 | Recording the intent digest | **Option (b).** Keep the gateway nonce; write a signed, hash-chained side correlation record tied to the log entry (§6.3). The raw digest is not the gateway nonce. No `translog` change. |
| O-8 | Publication | **Approved after revision.** `m3-circle` is pushed once this revision is reviewed and the branch is clean. |

## 11. Deferred — not Milestone 3

- **[X]** Multi-capability policies and delegation chains (`SPEC-ARC-GATE.md` §7).
- **[X]** Any change to the §A.4 assertions of `SPEC-X402-ARC.md`.
- **[X]** Any change to the enforcement point. Nothing in this specification
  requires one; §6 is met with configuration and this repository's own code.
- **[X]** User-controlled and modular (passkey) Circle wallets. C1 names
  developer-controlled wallets.
- **[X]** Facilitator implementation. The guard protects the signing side; the
  facilitator that submits an EIP-3009 authorization is out of scope.
- **[X]** StableFX itself, beyond binding the permits it requires (C8).
- **[X]** Any change to `spt-txn-pep/translog`, including a mode marker or a
  correlation field, unless explicitly approved later.
- **[X]** Anchoring the correlation file's head on Arc (§6.3 residual).
- **[X]** Tightening the EIP-3009 window to the token's expiry. This waits for an
  authenticated and enforced `valid_before ≤ token expiry` relationship (§4.1.3).
- **[X]** The Gateway guard's window rule and implementation, until [O-4] is
  decided.

Fix to existing behaviour, carried in M3 as a trust-boundary fix: strict tool
argument decoding (§3).

## 12. Tests that must exist

Besides §7, per rail:

- each independent control (§2.1) refuses alone, with the others removed or
  forced to approve;
- the post-signature recheck refuses a signature that recovers to another
  address, and a returned transaction that differs in any field;
- a known-answer test for the intent digest (§6), generated from the reference
  implementation, and a test that the gateway computes it over the arguments as
  received;
- a repeated `payment_id` is refused;
- startup refuses an empty or malformed `-server-identity`, and a call whose
  `server_identity` argument differs from it is refused;
- correlation records: a record moved to another log entry, edited, removed from
  the middle, or reordered is detected; a failure to persist a record means
  nothing is signed;
- the EIP-3009 window: `validBefore` past the capability expiry, the call expiry
  or the maximum lifetime is refused, as is `validAfter` in the future;
- observe mode cannot be started with a payment key or a wallet credential, and no
  input in observe mode produces a signature;
- every configuration value that is pinned (domain name and version, contract
  addresses, chain ids, CCTP domains) is refused at startup if absent or
  malformed.

## 13. Status — read before citing

This specification has been reviewed by the owner. Implementation of the P1 items
follows on this branch; until the README says otherwise, treat any item here as
not yet implemented. Nothing in this repository is externally audited. Evidence of a
payment, once produced, demonstrates the guarded path on the networks named and
nothing more.

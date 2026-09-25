# SPT-Txn × Arc — the authorization gate for agentic USDC

**A payment an AI agent proposes is signed only if it is *exactly* the payment a
human authorized. Otherwise nothing is signed.**

This repository is the **Arc + USDC** settlement path of the SPT-Txn
authorization engine. It contains one thing that matters: a pre-sign guard that
sits between "the policy said ALLOW" and "the key produced a signature", and
refuses to sign anything other than the bound payment.

- The chain-agnostic authorization core lives in
  [`spt-txn-pep`](https://github.com/rudizee007/spt-txn-pep).
- The Solana/SPL settlement path lives in
  [`spt-txn-x402-solana`](https://github.com/rudizee007/spt-txn-x402-solana),
  including the base spec this one extends.

---

## Why a guard, and not just a policy check

Policy runs on a *description* of a payment. Signatures are produced over a
*transaction*. Everything dangerous lives in the gap between the two: a builder
that was compromised, a facilitator that substituted a field, a prompt-injected
agent that got the policy to say yes to something the transaction does not
actually do.

So the guard does not trust the decision. It decodes the transaction that is
about to be signed, asserts it moves exactly the bound amount of the bound asset
to the bound recipient under the bound payer's authority — and nothing else —
and refuses on any mismatch. A policy engine that was wrong, bypassed, or
compromised still does not produce a signature for an unbound transfer.

## What makes Arc different, and harder

On Arc, **USDC is the native gas asset and an ERC-20 contract at the same time**:
one pool of funds, exposed through two interfaces at two scales — 18 decimals for
`msg.value` and gas, 6 decimals for `transfer` and `balanceOf`.

That has no Solana analogue, and it breaks the obvious guard. A transaction can
carry a *perfectly bound* 1-USDC `transfer()` in its calldata and simultaneously
move an arbitrary balance of the same funds through `value`. A guard that
inspects calldata authorizes the first and signs away the second.

The same shape appears twice more: the transaction fee is paid in the payment
asset, so an unbounded fee is an unbounded second payment; and an EIP-7702
transaction can pay the bound amount while its authorization list installs
attacker code at the payer's own account. All three are fields a guard *does not
model* — and a field that is not modelled is a field that is permitted.

`settle/evm` therefore pins the whole transaction, not just the payload. Twelve
assertions, one sentinel error each, specified in
[`docs/SPEC-X402-ARC.md`](docs/SPEC-X402-ARC.md) before a line of it was written.

## See it refuse

No key, no funds, no network:

```sh
CGO_ENABLED=0 go run -tags arc ./cmd/payarc -selftest
```

Builds thirteen adversarial transactions through real go-ethereum transaction
objects and proves each is refused by *its own* control — including one that is
invisible to the pre-sign guard by construction (it changes who signs, not what
is signed) and is caught by the post-sign re-check.

```
ok    clean-signed  signed, sender recovered as the payer, every field unchanged
ok    value        DENY_VIOLATION — settle/evm: transaction moves native value (must be 0)
ok    selector     DENY_VIOLATION — evm: calldata is not transfer(address,uint256)
ok    signer       DENY_VIOLATION — settle/evm: signed transaction differs from the verified transaction
...
every control fired as specified; 13 modes refused, nothing broadcast
```

Then settle for real on Arc testnet — see [`docs/RUNBOOK-ARC.md`](docs/RUNBOOK-ARC.md).

**Arc mainnet** moves real USDC and is never a default. It is reached only with
`-network mainnet`, and then `payarc` also requires an explicit `-amount` and a
`-key` file that is not the testnet default path (runbook §M).

### On Arc mainnet

The first guarded USDC transfer on Arc mainnet, recorded at the time it settled:

| What | Value |
|---|---|
| Transaction | [`0x88a8497510d02335d00b932fc9d1c4205fe06fb7e35e4cbfb9924bc1ceadf3cf`](https://explorer.arc.io/tx/0x88a8497510d02335d00b932fc9d1c4205fe06fb7e35e4cbfb9924bc1ceadf3cf) |
| Block / time | 22754544 · 2026-09-25 21:53:29 UTC |
| Network | Arc mainnet, chain id 5042 |
| Payer → recipient | `0x4788Ca19912c9d6c08b44698acF8F00C48bAa628` → `0x79A34Cc563f848f626038Ff312CCEBfb5374971d` |
| Amount | 10000 micro-USDC (0.01 USDC) |
| Fee | 0.0014861538 USDC (gas used 73938), under the 0.05 USDC ceiling |
| Code | `main` at `4f83afc` |

Decoding it on chain shows what was signed rather than what our tooling reports:
`to` is the USDC contract `0x3600…0000` (not a router), `value` is 0, the calldata
is exactly 68 bytes with selector `a9059cbb`, and it carries the bound recipient
and amount. The access list is empty and there is no authorization list.

## Layout

| Path | Build | What it is |
|---|---|---|
| `settle/evm/` | default | The guard. **Pure standard library** — no chain SDK, no third-party import. 100% statement coverage, property-tested over all 2¹⁵ corruption subsets, fuzzed. |
| `cmd/payarc/` | `-tags arc` | The only code that touches a key or the network. Excluded from `go build ./...` and `go test ./...`. |
| `docs/SPEC-X402-ARC.md` | — | The spec. Written before the code, as the trust boundary requires. |
| `docs/RUNBOOK-ARC.md` | — | Setup, the ALLOW, the DENY, and what is honest to claim. |

The guard's entire non-standard-library dependency closure is one package.
Check it rather than believing it:

```sh
go list -deps ./settle/evm | grep '\.'
```

```
github.com/rudizee007/spt-txn-pep/gate
github.com/rudizee007/spt-txn-x402-arc/settle/evm
```

Only the build-tagged command links go-ethereum. That is deliberate: it keeps
the code that decides whether to sign auditable in an afternoon, and it is why
this repository is separate from the Solana settler rather than a directory
inside it.

## Build constraints that are not suggestions

**cgo must be off.** go-ethereum links C `libsecp256k1` when cgo is enabled and
falls back to the audited pure-Go `decred/dcrd/dcrec/secp256k1` when it is not.
No C inside the trust boundary. `cmd/payarc/nocgo.go` makes a cgo build fail to
compile rather than leaving it to a line in a README, and CI asserts that the
failure still happens.

```sh
CGO_ENABLED=0 go build -tags arc ./cmd/payarc
```

**Licence.** This repository is Apache-2.0. go-ethereum's library is LGPL-3.0
and is linked only by the build-tagged demo command; the guard package itself
has no dependency and is unaffected.

## Status — read this before citing it

Nothing here is externally audited. Nothing is in production. It runs on Arc
testnet by default and on Arc mainnet only when named. It was built to a written spec, adversarially reviewed twice in fresh context, and
it should be treated as exactly that.

The bound payment in `cmd/payarc` is declared on the command line, **not**
consumed from a live gate decision. What this repository demonstrates is that
the settlement path cannot deviate from the payment it was told to make. Wiring
it to a live policy decision is the MCP gateway path in the Solana repository and
is not yet ported here. Saying so is the point.

## Security

See [`SECURITY.md`](SECURITY.md). Report privately to
**rudi@violetskysecurity.com**.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).

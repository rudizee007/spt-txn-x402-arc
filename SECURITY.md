# Security

## Reporting a vulnerability

Report privately to **rudi@violetskysecurity.com**. Please allow reasonable time
for remediation before public disclosure; coordinated disclosure is appreciated.

The chain-agnostic authorization core is a separate repository with its own
policy: [`spt-txn-pep`](https://github.com/rudizee007/spt-txn-pep).

## What this code is trusted to do

One thing: **decide whether a transaction may be signed.** Everything else here
exists to exercise that decision. The trust boundary is `settle/evm`, and it is
small on purpose — a guard that cannot be read end to end in an afternoon is a
guard nobody checks.

Five properties carry the weight.

**The guard does not trust the decision that preceded it.** It decodes the
transaction that is about to be signed and asserts, independently, that it moves
exactly the bound amount of the bound asset to the bound recipient under the
bound payer's authority. A policy engine that was wrong, bypassed, or
compromised still produces no signature for an unbound transfer.

**Fields that are not modelled are refused, not permitted.** A transaction is an
open structure. The guard pins the EIP-1559 envelope type and requires the
access, authorization and blob lists to be empty, because a guard that checks
`to`/`value`/`data` and says nothing about the type will certify an EIP-7702
payload that pays the bound amount *and* installs attacker code at the payer's
own account. Silence is not a check.

**Native value and the fee are bound, because on Arc they are the payment
asset.** USDC there is simultaneously the gas token and the ERC-20 — one pool of
funds, 18 decimals natively and 6 through the contract. A calldata-only guard
authorizes a bound 1-USDC transfer while `value` drains the balance, so `value`
must be zero and `gasLimit × maxFeePerGas` must be under an explicit ceiling. The
10¹² scale factor between the two views is verified against the chain on every
run rather than assumed, because a constant nobody checks is a guess.

**A verdict cannot go stale.** `Verify` copies the transaction, asserts against
the copy, and returns that copy as proof. A caller cannot mutate a `*big.Int` or
extend a calldata slice in place after the check. After signing, every field is
read back off the signed object and the sender is recovered from the signature,
then compared field-for-field against what was verified. A signature that does
not match is discarded, never broadcast.

**No custom cryptography and no C.** The guard computes no hashes and holds no
keys; it is byte comparison and integer arithmetic over the standard library.
The one hardcoded constant — the ERC-20 `transfer` selector — is re-derived from
an audited Keccak on every run of the settlement command and disagreement is
fatal. go-ethereum's C `libsecp256k1` is excluded by a deliberate compile error
under cgo (`cmd/payarc/nocgo.go`), asserted in CI.

## What this code is *not* trusted to do

- **It does not authorize.** The policy decision is `spt-txn-pep`'s. This guard
  is the last line, not the first.
- **It does not establish that a payment was authorized end to end.** In
  `cmd/payarc` the bound payment is operator-declared, not consumed from a gate
  ALLOW.
- **It does not defend against a hostile RPC endpoint beyond what it can check.**
  It refuses a disagreeing chain id, refuses a pending/confirmed nonce gap,
  refuses an implausible gas estimate, and verifies the decimal ratio — but the
  endpoint is still an unauthenticated third party. `-rpc` is required and has
  no default for that reason.
- **It has not been externally audited**, and nothing here is in production.

## Reviewing it

The guard is `settle/evm/{address,transfer,guard,arc,binding}.go`. Read
[`docs/SPEC-X402-ARC.md`](docs/SPEC-X402-ARC.md) §A.4 first; it is normative and
was written before the code. Every rule phrased as absolute is there because an
adversarial review broke the version without it — §A.8 records which.

`go run -tags arc ./cmd/payarc -selftest` runs every adversarial case offline
with an ephemeral key and no network. A finding that this misses a case is a
more useful bug report than one against any other file here.

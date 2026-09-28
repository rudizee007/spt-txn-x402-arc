# Runbook — USDC settlement on Arc testnet (M1-Arc)

What this gets you: a real Arc testnet transaction hash for the ALLOW, and a
demonstrated refusal for each of thirteen distinct attacks. Spec:
[`SPEC-X402-ARC.md`](SPEC-X402-ARC.md). Read §A.0 before recording anything — the scope of what
this proves is narrower than "SPT-Txn authorized a payment", and saying so is
the difference between a credible submission and one a reviewer picks apart.

---

## 0. Layout

| Path | Build | What it is |
|---|---|---|
| `docs/SPEC-X402-ARC.md` | — | The spec. Written before the code. |
| `settle/evm/` | **default** | The pre-sign guard. Pure standard library, no chain SDK, 100% statement coverage, property-tested and fuzzed. |
| `cmd/payarc/` | `-tags arc` | The only code that touches keys or the network. Excluded from `go build ./...` and `go test ./...`. |

This repository is deliberately separate from
[`spt-txn-x402-solana`](https://github.com/rudizee007/spt-txn-x402-solana). Arc is an additional settler behind the
same discipline, not a replacement — but it needs go-ethereum and ~26
transitive modules, and the Solana repository's dependency story is "one chain
SDK and the PEP". Keeping the two apart is what lets each guard stay auditable
in an afternoon.

**Nothing here is committed.** The maintainer line-by-line review is step 6 of
§A.8 and is not delegable.

---

## 1. One-time setup

> **zsh warning.** zsh does not treat `#` as a comment in an interactive shell
> unless `setopt interactivecomments` is set, so a pasted `go test ./... # note`
> becomes `go test ./... '#' note` and fails with *malformed import path "#"*.
> Every command block below is comment-free for that reason.

```sh
cd ~/Claude/Projects/'SPT-TXN POC'/spt-txn-x402-arc
go mod tidy
go build ./... && go test ./... -race
```

`go.mod` declares go-ethereum; `go mod tidy` writes `go.sum`. Two things to
decide before you commit that:

- **go-ethereum's library is LGPL-3.0**; this repo is Apache-2.0. The guard
  package takes no dependency and stays clean — only the build-tagged demo
  command links it, and it is not part of any distributed artifact. Probably
  fine. Still your call, not a detail to meet in a procurement review.
- **cgo must be off.** go-ethereum links C `libsecp256k1` when cgo is enabled
  and falls back to the audited pure-Go `decred/dcrd/dcrec/secp256k1` when it
  is not. CLAUDE.md forbids C inside the trust boundary. `cmd/payarc/nocgo.go`
  makes a cgo build fail to compile rather than leaving it to a README line,
  and CI asserts the failure still happens. Confirm both:

```sh
CGO_ENABLED=1 go build -tags arc ./cmd/payarc
CGO_ENABLED=0 go build -tags arc ./cmd/payarc
```

The first MUST fail with `undefined: payarcRequiresCGO_ENABLED_0_seeThisFile`.
The second MUST succeed.

**Every tool you point at the tagged path needs `CGO_ENABLED=0` too.** The guard
is a compile error, so anything that type-checks `-tags arc` — `govulncheck`,
`staticcheck`, `gopls`, your editor's language server — hits it and reports
`undefined: payarcRequiresCGO_ENABLED_0_seeThisFile` instead of doing its job.
That is the guard working, not a bug, but it is a surprise the first time:

```sh
CGO_ENABLED=0 govulncheck -tags arc ./...
```

For an editor, set `CGO_ENABLED=0` and the `arc` build tag in the Go language
server settings, or `cmd/payarc` will show as one long red squiggle.

---

## 2. Prove the controls fire — offline, no key, no funds

```sh
CGO_ENABLED=0 go run -tags arc ./cmd/payarc -selftest
```

Builds every adversarial transaction, drives each through a real go-ethereum
transaction object, and asserts each is refused by *its own* sentinel. Uses an
ephemeral in-memory key so the signing leg is real; broadcasts nothing. Expect
`every control fired as specified` and exit 0.

`-tamper list` prints all thirteen with the assertion each trips.

Twelve are pre-sign. One — `signer` — is invisible to the pre-sign guard by
construction (it changes *who signs*, not what is signed) and is caught by the
post-sign re-check. That one is the reason the post-sign leg exists, and it is
worth showing on camera.

---

## 3. Get a key and some testnet USDC

```sh
mkdir -p ~/.config/spt-txn && chmod 700 ~/.config/spt-txn
(umask 077 && openssl rand -hex 32 > ~/.config/spt-txn/arc.key)
```

The command refuses a key file that is group- or world-readable, a key path that
is not a regular file, and a containing directory that group or others can write
to or that is owned by anyone but you or root. It never reads the key from an
environment variable and never prints it.

To learn the address to fund, run any command — it prints `payer:` before it
does anything else. Then fund that exact address with Arc testnet USDC at
<https://faucet.circle.com> (select Arc testnet).

On Arc, USDC is both the gas token and the ERC-20. One faucet drip covers both.

---

## 4. Confirm the RPC endpoint

Public sources disagree, so `-rpc` is required and has no default:

- Arc's own docs: `https://rpc.testnet.arc.io`
- Circle's `use-arc` skill: `https://rpc.testnet.arc.network`

Check which one is live before you record:

```sh
curl -s -X POST https://rpc.testnet.arc.io \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
# expect {"jsonrpc":"2.0","id":1,"result":"0x4cef52"}   (5042002)
```

The command refuses to settle if the endpoint reports any other chain id.

---

## 5. The ALLOW — a real transaction hash

```sh
export ARC_RPC=https://rpc.testnet.arc.io      # or whichever answered above

CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc "$ARC_RPC" -amount 100000 -dry-run
```

That is everything except the signature. Then for real, paying 0.10 USDC to
yourself:

```sh
CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc "$ARC_RPC" -amount 100000
```

Or to a merchant:

```sh
CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc "$ARC_RPC" -to 0xMERCHANT -amount 100000
```

Ends with an explorer link at `https://testnet.arcscan.app/tx/…`. **That link is
milestone M1's deliverable.** Save it.

If you have the payTo identifier as the gate carries it (base58 of the widened
32-byte account id), pass `-bound-payto <string>` and the command will check it
denotes `-to`. Without it the command prints the encoding and says plainly that
it did not check it — a value compared against itself is not a control, and
printing one as though it were is worse than not checking.

---

## 6. The DENY — the shot that actually sells this

```sh
CGO_ENABLED=0 go run -tags arc ./cmd/payarc -rpc "$ARC_RPC" -tamper value
```

Pick the mode for the story you are telling:

| Mode | The story |
|---|---|
| `value` | **The strongest one on Arc.** Calldata is a perfect, bound 1-USDC transfer; `value` moves 1 USDC of *the same funds* through the native interface. A calldata-only guard signs it. No Solana equivalent exists. |
| `recipient` | The classic: an injected agent redirects the payment to an attacker. |
| `amount` | The injected agent inflates the amount 1000×. |
| `selector` | `approve` instead of `transfer` — standing authority instead of a payment. This is the thesis of the product in one flag. |
| `signer` | A perfectly bound transaction signed by an unauthorized key. Passes the pre-sign guard, dies on the post-sign check. |
| `gas` | The fee dwarfs the payment — in the same asset. Unique to a chain where gas *is* the money. |

Each prints `DENY_VIOLATION`, names which assertion fired, and states that
nothing was signed (or, for `signer`, that a signature exists and is being
discarded). Nothing is broadcast. Nothing moves.

---

## 7. For the recording

- Screen-share **only** `spt-txn-x402-arc`. No other repository in an editor
  tab, a terminal title, a shell prompt, or a browser tab — and note that the
  repository name on camera is now Arc's, which is part of why it exists.
- What is honest to claim: *the settlement path cannot deviate from the payment
  it was told to make, on Circle's chain, in Circle's asset, and here is the
  transaction hash and thirteen refusals proving it.*
- What is **not** honest to claim from `cmd/payarc` alone: that an end-to-end
  authorization was enforced. This command's bound payment is declared on the
  command line, not consumed from a gate ALLOW. The gate-driven path is
  `cmd/mcp-gateway` in the Solana repository, and is not ported here. Say which
  is which; a reviewer who finds the gap themselves discounts everything else
  you said.
- Also true and worth saying once, plainly: nothing here is externally audited
  and nothing is in production.

---

## 8. Known gaps, named

- **No gate-driven path here.** `cmd/mcp-gateway` lives in the Solana
  repository and hardcodes `solana:devnet` and the Solana USDC mint. Porting it
  is the next step: either move the network/asset behind build tags there, or
  add an Arc-flavoured MCP gateway here that imports `spt-txn-pep` directly. The
  second is probably cleaner now the repositories are split.
- **No receipt.** `settle/evm` emits none; the transparency log lives in
  `spt-txn-pep` and is chain-agnostic, but nothing here calls it. Anchoring the
  Merkle root via Arc's Memo contract at
  `0x5294E9927c3306DcBaDb03fe70b92e01cCede505` is the obvious next move.
  Optional for M1.
- The demo shows base58 of a padded 20-byte address where a reviewer expects
  `0x…`. That is §A.2's named wart; the clean fix is a network-scoped address
  codec in `spt-txn-pep`, which is a trust-boundary change to a published
  dependency and carries the full review loop.
- The Solana repository assigns two different allowlist tags to `solana:devnet`
  (`1` in `cmd/escrowdevnet` and `escrow/link_test.go`, `2` everywhere else).
  Tags are per-deployment configuration so nothing is broken, but two values for
  one network in one deployment is the confusable state §4 sets out to remove.
  Out of scope here; worth fixing there.

---

## M. Arc mainnet — real USDC

Mainnet is never a default. Everything above is testnet.

1. **Use a key used only for mainnet.** Do not reuse `~/.config/spt-txn/arc.key`,
   which the testnet steps create; `payarc` refuses that path on mainnet.
   ```bash
   umask 077 && openssl rand -hex 32 > ~/.config/spt-txn/arc-mainnet.key
   ```
2. **Fund it with a little USDC on Arc mainnet.** There is no faucet. About $1 covers
   a 0.01 USDC transfer many times over; on 2026-09-23 gas was ~20 gwei, which is
   roughly 0.0013 USDC per transfer.
3. **Dry run first** (asserts, never signs):
   ```bash
   CGO_ENABLED=0 go run -tags arc ./cmd/payarc -network mainnet \
     -rpc https://rpc.mainnet.arc.io -key ~/.config/spt-txn/arc-mainnet.key \
     -to 0x<second address you control> -amount 10000 -dry-run
   ```
4. **Settle:** the same command without `-dry-run`. Record the transaction hash
   and block at once (spt-poc STATUS.md sets the rule: record the hash at deploy
   time).
5. Remove or move the key file off the machine when finished.

**First mainnet settlement (recorded 2026-09-25):** tx
`0x88a8497510d02335d00b932fc9d1c4205fe06fb7e35e4cbfb9924bc1ceadf3cf`, block 22754544,
0.01 USDC from `0x4788…a628` to `0x79A3…971d`, fee 0.0014861538 USDC. Dry run first
(`guard: PASS`), then settle (`guard: PASS`, `post-sign: PASS`, `SETTLED`). Details in the
README.

## G. `arc-gateway` install layout (Linux)

Where a client installation keeps the gateway's files. The rules it must meet are
in `docs/SPEC-ARC-GATE.md` §6; this layout meets them on stock Linux and RHEL.

```text
Signed log, counts, checkpoint:  /var/lib/spt-txn-arc/          service user, 0700
-state-dir:                      /var/lib/spt-txn-arc/state/    service user, 0700
Keys and approval file:          /etc/spt-txn-arc/              root:spt-arc 0750
                                 key files owned by spt-arc, 0400 or 0600
Diagnostics:                     stderr → journald
```

- **Key files are owned by the service user** (`spt-arc`) with mode 0400 or 0600.
  The key check refuses any group or other permission, so a key readable only
  through the group (`root:spt-arc 0440`) is refused, and a key owned by root
  with mode 0400 cannot be read by the service.
- **Not `/var/log`.** The signed log is state, not a text log: log rotation would
  rename or truncate it and break its signatures and its match with the on-chain
  checkpoints, and on some distributions `/var/log` is group-writable, which the
  gateway refuses.
- **Use a fixed service user**, not `DynamicUser=`, so the files keep one owner
  across restarts.
- **Symlinks on the path:** one owned by root in a directory that passes the rules
  is followed (for example `/home` → `/usr/home` on FreeBSD, `/var` and `/tmp` on
  macOS); any other symlink is refused, with a message naming it.
- **`-log` and `-state-dir` are required, have no default, and must be absolute
  paths.** The directory above `-state-dir` must exist; the gateway creates the
  state directory itself, mode 0700.
- **Installing under a user account** (for example an agent host run by a person):
  use an absolute path the account owns, such as `$HOME/.local/state/spt-txn-arc/`
  on Linux or `~/Library/Application Support/spt-txn-arc/` on macOS, mode 0700.
- **OpenBSD:** a dedicated `/var/<daemon>` directory owned by the service user,
  mode 0700, not a group-shared 770 directory.

**How it runs.** `arc-gateway` is an MCP server over stdin and stdout, started as a
subprocess by the MCP host (the agent runtime), once per host session. It is not a
network daemon and is not started per connection. Run the MCP host as the service
user, and the gateway inherits that account. When the host itself runs under
systemd or in a container, give the host process:

- `User=spt-arc` (a fixed account, not `DynamicUser=`)
- `StateDirectory=spt-txn-arc` and `StateDirectoryMode=0700`
- `ProtectSystem=strict` and `ReadWritePaths=/var/lib/spt-txn-arc`
- `NoNewPrivileges=yes` and `PrivateTmp=yes`

and register the gateway with the host using absolute paths, for example:

```text
/usr/local/bin/arc-gateway \
  -capability /etc/spt-txn-arc/capability.json \
  -rpc https://rpc.mainnet.arc.io \
  -verify-rpc <a second, independent Arc endpoint> \
  -key /etc/spt-txn-arc/pay.key \
  -checkpoint-key /etc/spt-txn-arc/checkpoint.key \
  -log-key /etc/spt-txn-arc/log.key \
  -log /var/lib/spt-txn-arc/decisions.json \
  -state-dir /var/lib/spt-txn-arc/state
```

**One instance per approval.** Exactly one gateway may serve an approval at any
moment, including during upgrades. On one machine with one state directory this
is enforced: a second gateway finds the log and capability locks held and exits
with a refusal. The locks and counts are local to that machine, so two gateways
on different machines or with different volumes do not see each other, and each
would enforce the approval on its own; the deployment must prevent that.

**Containers.** A layout that passes the gateway's checks:

- Run as a non-root user (for example uid 10001), with a read-only root file
  system.
- Create `/var/lib/spt-txn-arc` in the image, owned by that user, mode 0700. Mount
  a Docker/Podman named volume there (on first use it takes the image directory's
  owner and mode), or a block-backed ReadWriteOnce volume on Kubernetes whose
  directory an init step has given to that user with mode 0700.
- Put the keys in a directory owned by the container user, mode 0700, with the
  key files owned by that user, mode 0400 or 0600. A Kubernetes Secret volume
  cannot be used directly as the key directory: its entries are symlinks into
  `..data`, its directory mode is not owner-only, and Kubernetes cannot give each
  file an owner, so the gateway refuses it. Copy the keys from the Secret into
  such a directory with an init container, or use a baked-in or bind-mounted
  directory with the same ownership.
- On Kubernetes, run one replica and never overlap two: `strategy: Recreate` for a
  Deployment, or a StatefulSet with `replicas: 1` and a ReadWriteOnce volume
  (`ReadWriteOncePod`, where available, limits the volume to a single pod). A
  rolling update starts the new pod before the old one stops, which is two
  instances.

These are refused, by design, with a message naming the directory:

- a Kubernetes `emptyDir` (created mode 0777, no sticky bit);
- a volume with `fsGroup` set (group-writable, shared with every container in the
  pod that has that group);
- a host directory bind-mounted into a rootless or user-namespaced container, when
  its owner is not mapped and it appears as `nobody` (65534);
- a Kubernetes Secret volume used as the key directory (see above).

Network and shared volumes (NFS, AWS EFS, Azure Files, CephFS) are not supported
and are not detected: the gateway checks owners and modes, not the file-system
type, so such a volume can pass the checks while `flock` on it is not reliable.
Do not use them for the log or the state directory.

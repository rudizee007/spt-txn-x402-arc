#!/usr/bin/env bash
# Mutation check for the settle/evm constructor guards
# (settle/evm NewBoundPayment). Modelled on spt-txn-x402-base's
# scripts/mutate-review7-base.sh: one mutation per control, each MUST be
# killed by the named test, and a mutation that fails to apply is an error,
# never a skip. A fix without a test that goes red without it is a claim.
#
#   G-1  NewBoundPayment stops snapshotting Amount (validates and stores the
#         CALLER'S big.Int)
#   G-2  NewBoundPayment stops snapshotting MaxGasCost (same window)
#   G-3  ChainID == 0 is accepted again
#   G-4  Amount == 0 is accepted again (zero authorizes nothing, burns the nonce)
#   G-5  MaxGasCost == 0 is accepted again (a ceiling nobody chose, on a chain
#         where the fee is a second payment out of the payment asset)
#
# NOTE ON WHERE IT RUNS. settle/evm documents itself as dependency-free and
# offline-testable, and guard.go/address.go/transfer.go/arc.go are; but
# binding.go imports github.com/rudizee007/spt-txn-pep/gate, and go.mod pins a
# Go toolchain and go-ethereum that an offline reviewer's environment may not
# have. So this harness copies the package MINUS binding.go/binding_test.go
# into a throwaway stdlib-only module and mutates the COPY. The anchors are
# still validated against the real source (the copy is byte-identical), the
# repository tree is never written to, and the run is the same on a
# fully-provisioned machine. binding.go carries none of these controls.
#
# NOTE ON -race. The own-copies regression test deliberately races an
# unsynchronized *big.Int -- the race IS the defect -- and carries
# //go:build !race. This harness therefore runs WITHOUT -race, or that test is
# not compiled and G-1/G-2 score as killed for the wrong reason. Run
# `go test -race ./settle/...` separately for the rest.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
SRC=settle/evm
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

mkdir -p "$SCRATCH/evm"
printf 'module scratch/x402arc\n\ngo 1.24\n' > "$SCRATCH/go.mod"
stage() {
  local f
  for f in "$SRC"/*.go; do
    case "$(basename "$f")" in
      binding.go|binding_test.go) ;;
      *) cp "$f" "$SCRATCH/evm/" ;;
    esac
  done
}
stage
if ! (cd "$SCRATCH" && go build ./evm >/dev/null 2>&1); then
  echo "FAIL      the clean extract of $SRC does not build in a stdlib-only module."
  echo "          Nothing below can be trusted until it does."
  (cd "$SCRATCH" && go build ./evm 2>&1 | sed 's/^/          /')
  exit 1
fi

# run_mutation <name> <want_test> <file-basename> <from> <to> [want_n]
#   want_test may be Top/Sub; -list can only see Top, -run gets the whole thing.
run_mutation() {
  local name="$1" want_test="$2" file="$3" from="$4" to="$5" want_n="${6:-1}"
  local top="${want_test%%/*}"
  stage
  if [ -z "$( (cd "$SCRATCH" && go test ./evm -list "^${top}\$" 2>/dev/null) | grep -E '^Test')" ]; then
    echo "FAIL      $name: $top matches no test in $SRC -- fix the mapping, do not skip it"
    return 1
  fi
  # A test that fails on the CLEAN tree also fails under mutation and scores as
  # "killed" -- a false green. Assert it passes before trusting that it failed.
  if ! (cd "$SCRATCH" && go test ./evm -run "^${want_test}\$" -count=1 >/dev/null 2>&1); then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  # The apply step MUST fail loudly. A bare heredoc discards python's exit
  # status, so a stale or ambiguous anchor leaves the file untouched, the test
  # passes against clean code, and the script prints SURVIVED.
  if ! python3 - "$SCRATCH/evm/$file" "$from" "$to" "$want_n" <<'PY'
import sys
p, a, b, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
s = open(p).read()
assert s.count(a) == n, f"anchor appears {s.count(a)} times, expected {n}"
open(p, "w").write(s.replace(a, b))
PY
  then
    echo "FAIL      $name: anchor did not match exactly $want_n time(s) -- the mutation"
    echo "          was NOT applied, so a pass below would mean nothing. Re-anchor it."
    return 1
  fi
  if ! (cd "$SCRATCH" && go build ./evm >/dev/null 2>&1); then
    echo "FAIL      $name: mutation does not compile -- rewrite it, do not skip it"
    return 1
  fi
  if (cd "$SCRATCH" && go test ./evm -run "^${want_test}\$" -count=1 >/dev/null 2>&1); then
    echo "SURVIVED  $name -- $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0
G=guard.go

# G-1 -- the amount is validated and stored through the caller's pointer.
run_mutation "G-1 amount validated through the caller pointer" \
  "TestNewBoundPayment_UsesItsOwnCopies/Amount" "$G" \
  "	amount := cloneBig(b.Amount)" \
  "	amount := b.Amount" || rc=1

# G-2 -- the gas ceiling is validated and stored through the caller's pointer.
run_mutation "G-2 gas ceiling validated through the caller pointer" \
  "TestNewBoundPayment_UsesItsOwnCopies/MaxGasCost" "$G" \
  "	maxGasCost := cloneBig(b.MaxGasCost)" \
  "	maxGasCost := b.MaxGasCost" || rc=1

# G-3 -- an unset chain id is bound, and Verify's chain pin is 0 == 0.
run_mutation "G-3 ChainID == 0 accepted" \
  "TestNewBoundPayment_Rejections/zero_chain_id" "$G" \
  "	if b.ChainID == 0 {" \
  "	if false && b.ChainID == 0 {" || rc=1

# G-4 -- a zero amount is bound again.
run_mutation "G-4 Amount == 0 accepted" \
  "TestNewBoundPayment_Rejections/zero_amount" "$G" \
  "	if amount == nil || amount.Sign() <= 0 || amount.BitLen() > boundAmountBits {" \
  "	if amount == nil || amount.Sign() < 0 || amount.BitLen() > boundAmountBits {" || rc=1

# G-5 -- a zero fee ceiling is bound again.
run_mutation "G-5 MaxGasCost == 0 accepted" \
  "TestNewBoundPayment_Rejections/zero_gas_ceiling" "$G" \
  "	if maxGasCost == nil || maxGasCost.Sign() <= 0 {" \
  "	if maxGasCost == nil || maxGasCost.Sign() < 0 {" || rc=1

echo
if [ $rc -eq 0 ]; then
  echo "All mutations killed. Every constructor control in settle/evm has a test that fails without it."
else
  echo "At least one mutation SURVIVED or the harness failed. Read the lines above."
fi
echo
echo "NOT COVERED, and honestly so:"
echo "  G-6  the line that drops the caller's pointers from the local Binding"
echo "        (b.Amount, b.MaxGasCost = nil, nil). With G-1/G-2 in place nothing"
echo "        after it reads those fields, so removing it changes no behaviour and"
echo "        no test can go red. It is defence in depth against a future edit"
echo "        that re-reads b.Amount; an unkillable mutation would report SURVIVED"
echo "        forever and train the reader to ignore this file. Recorded instead."
exit $rc

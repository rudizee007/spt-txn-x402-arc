#!/usr/bin/env bash
# Mutation check for the correlation chain (correlation), SPEC-ARC-M3 §6.3 (0x01 and 0x02).
# Each mutation removes or weakens one control. It MUST be killed by the named
# test. A mutation whose anchor is not found exactly once is an error, never a
# skip. The repository tree is never written to; a copy is mutated.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM
cp -r . "$SCRATCH/repo"
F="$SCRATCH/repo/correlation/correlation.go"
ORIG=$(cat "$F")

fail=0
# mutate <name> <test regexp> <from> <to>
mutate() {
  local name="$1" want="$2" from="$3" to="$4"
  printf '%s' "$ORIG" > "$F"
  local n
  n=$(FROM="$from" python3 -I -c 'import os,sys; print(sys.stdin.read().count(os.environ["FROM"]))' < "$F")
  if [ "$n" != "1" ]; then
    echo "ERROR     $name: anchor found $n times"
    fail=1
    return
  fi
  FROM="$from" TO="$to" python3 -I -c 'import os,sys; s=sys.stdin.read(); sys.stdout.write(s.replace(os.environ["FROM"], os.environ["TO"], 1))' < "$F" > "$F.new" && mv "$F.new" "$F"
  if (cd "$SCRATCH/repo" && go test ./correlation/ -run "$want" >/dev/null 2>&1); then
    echo "SURVIVED  $name (want killed by $want)"
    fail=1
  else
    echo "killed    $name"
  fi
}

mutate "completion may reference a later or missing record" TestMalformedCompletionsAreRefused \
  '	case !ok:
		return fmt.Errorf("%w: %w: names no earlier authorization record (ref %d)", ErrCorrupt, ErrReference, c.RefSeq)' '	case !ok && false:
		return nil'
mutate "completion may reference any rail" TestMalformedCompletionsAreRefused \
  'case recs[i].Rail != RailEIP3009:' 'case false:'
mutate "ref_hash unchecked" TestMalformedCompletionsAreRefused \
  'case recs[i].Hash() != c.RefHash:' 'case false:'
mutate "identity unchecked" TestMalformedCompletionsAreRefused \
  'case recs[i].GuardedID != c.GuardedID || recs[i].PaymentID != c.PaymentID:' 'case false:'
mutate "duplicate completion in file allowed" TestMalformedCompletionsAreRefused \
  'case done[c.RefSeq]:' 'case false:'
mutate "duplicate completion on append allowed" TestMixedChainRoundTripAndReopen \
  'if _, dup := c.completions[refSeq]; dup {' 'if false {'
mutate "append may complete any rail" TestMixedChainRoundTripAndReopen \
  'if r.Rail != RailEIP3009 {' 'if false {'
mutate "completions not restored on reopen" TestMixedChainRoundTripAndReopen \
  '		cf.completions[c.RefSeq] = c' '		_ = c'
# Equivalent mutant, excluded: treating an unknown layout as 0x01 is still
# refused by decode's own layout check. Both layers are kept on purpose.
mutate "torn entry tolerated" TestStructuralCorruptionIsRefused \
  '		if len(raw)-off < entLen {' '		if len(raw)-off < entLen { break }; if false {'
mutate "chain link unchecked" TestStructuralCorruptionIsRefused \
  '		case prev != ch.Last:' '		case false:'
mutate "failed write remembered" TestCompletionWriteFailureFailsClosed \
  '	if err := c.write(cp.Encode(), key); err != nil {
		return Completion{}, err
	}' '	_ = c.write(cp.Encode(), key)'
mutate "0x01 encoding changed" TestGoldenV1 \
  '	b = append(b, r.Rail)' '	b = append(b, r.Rail^1)'

if [ "$fail" -ne 0 ]; then
  echo "FAIL: a mutation survived or did not apply"
  exit 1
fi
echo "PASS: every mutation was killed"

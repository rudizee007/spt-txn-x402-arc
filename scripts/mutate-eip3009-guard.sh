#!/usr/bin/env bash
# Mutation check for the EIP-3009 guard (settle/eip3009), SPEC-ARC-M3 §7.
# Each mutation removes or weakens one control. It MUST be killed by the named
# test. A mutation whose anchor is not found exactly once is an error, never a
# skip. The repository tree is never written to; a copy is mutated.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM
cp -r . "$SCRATCH/repo"
F="$SCRATCH/repo/settle/eip3009/eip3009.go"
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
  if (cd "$SCRATCH/repo" && go test ./settle/eip3009/ -run "$want" >/dev/null 2>&1); then
    echo "SURVIVED  $name (want killed by $want)"
    fail=1
  else
    echo "killed    $name"
  fi
}

mutate "A1 asset contract unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.Domain.VerifyingContract != w.Domain.VerifyingContract:' 'case false:'
mutate "A2 chain unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.Domain.ChainID != w.Domain.ChainID:' 'case false:'
mutate "A2 domain name/version unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.Domain.Name != w.Domain.Name || a.Domain.Version != w.Domain.Version:' 'case false:'
mutate "A3 primary type unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.PrimaryType != PrimaryType:' 'case false:'
mutate "A4 payer unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.From.IsZero() || a.From != w.From:' 'case false:'
mutate "A5 recipient unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.To != w.To:' 'case false:'
mutate "A6 amount unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.Value == nil || a.Value.Cmp(w.Value) != 0:' 'case a.Value == nil:'
mutate "A7 validAfter unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'a.ValidAfter.Cmp(big.NewInt(b.now)) > 0:' 'false:'
mutate "A7 validBefore ceiling unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.ValidBefore == nil || a.ValidBefore.Cmp(w.ValidBefore) > 0:' 'case a.ValidBefore == nil:'
mutate "A7 closed window accepted" TestEveryMutationIsRefusedByItsAssertion \
  'case a.ValidBefore.Cmp(a.ValidAfter) <= 0 || a.ValidBefore.Cmp(big.NewInt(b.now)) <= 0:' 'case false:'
mutate "A8 nonce unchecked" TestEveryMutationIsRefusedByItsAssertion \
  'case a.Nonce != w.Nonce:' 'case false:'
mutate "O-1 raw digest used as nonce" TestBindConstructsTheBoundAuthorization \
  'Nonce:       intent.EIP3009Nonce(b.Intent),' 'Nonce:       [32]byte(b.Intent),'
mutate "O-3 capability expiry ignored" TestWindowIsTheEarliestLimit \
  'end := b.CapabilityExpiry' 'end := b.CallExpiry'
mutate "O-3 max lifetime ignored" TestWindowIsTheEarliestLimit \
  'if lim := now.Add(b.MaxLifetime); lim.Before(end) {' 'if lim := now.Add(b.MaxLifetime); false && lim.Before(end) {'
mutate "O-3 rounding up" TestWindowIsTheEarliestLimit \
  'validBefore := end.Unix()' 'validBefore := end.Add(999 * time.Millisecond).Unix()'
mutate "O-3 expired window bound" TestWindowIsTheEarliestLimit \
  'if validBefore <= now.Unix() {' 'if false {'
mutate "A9 high-s accepted" TestCheckSignedFormAndSigner \
  'if s.Cmp(secpHalfN) > 0 {' 'if false {'
mutate "A9 any recovered signer accepted" TestCheckSignedFormAndSigner \
  'if recovered.IsZero() || recovered != b.auth.From {' 'if recovered.IsZero() {'
mutate "A9 v unchecked" TestCheckSignedFormAndSigner \
  'if v := sig[64]; v != 27 && v != 28 && v != 0 && v != 1 {' 'if v := sig[64]; false && v == 0 {'
mutate "Bind zero amount accepted" TestBindRefusesAnIncompleteBinding \
  'case b.Value == nil || b.Value.Sign() <= 0 || b.Value.Cmp(maxUint256) > 0:' 'case b.Value == nil:'
mutate "digest omits the verifying contract" TestDigestKnownAnswers \
  'word(new(big.Int).SetUint64(a.Domain.ChainID)), addressWord(a.Domain.VerifyingContract))' 'word(new(big.Int).SetUint64(a.Domain.ChainID)), addressWord(evm.Address{}))'

if [ "$fail" -ne 0 ]; then
  echo "FAIL: a mutation survived or did not apply"
  exit 1
fi
echo "PASS: every mutation was killed"

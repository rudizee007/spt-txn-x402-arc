#!/usr/bin/env bash
# Mutation check for the x402 v2 payload builder (x402v2), SPEC-ARC-M3 §4.1.5.
# Each mutation removes or weakens one control. It MUST be killed by the named
# test. A mutation whose anchor is not found exactly once is an error, never a
# skip. The repository tree is never written to; a copy is mutated.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM
cp -r . "$SCRATCH/repo"
F="$SCRATCH/repo/x402v2/payload.go"
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
  if (cd "$SCRATCH/repo" && go test ./x402v2/ -run "$want" >/dev/null 2>&1); then
    echo "SURVIVED  $name (want killed by $want)"
    fail=1
  else
    echo "killed    $name"
  fi
}

mutate "payTo not compared" TestRefusals \
  'if a, err := parseAddress(payTo); err != nil || a != auth.To {' 'if _, err := parseAddress(payTo); err != nil {'
mutate "asset not compared" TestRefusals \
  'if a, err := parseAddress(asset); err != nil || a != auth.Domain.VerifyingContract {' 'if _, err := parseAddress(asset); err != nil {'
mutate "amount not canonical" TestRefusals \
  'if !canonicalUint(amount) {' 'if false {'
mutate "amount not compared" TestRefusals \
  'if n, _ := new(big.Int).SetString(amount, 10); n.Cmp(auth.Value) != 0 {' 'if n, _ := new(big.Int).SetString(amount, 10); n == nil {'
mutate "network not compared to configuration" TestNoPayloadWithoutAGuardedSignature \
  'if err != nil || network != cfg.Network {' 'if err != nil {'
mutate "scheme not compared" TestRefusals \
  'if err != nil || scheme != "exact" {' 'if err != nil {'
mutate "domain name not compared" TestRefusals \
  'if err != nil || name != auth.Domain.Name {' 'if err != nil {'
mutate "domain version not compared" TestRefusals \
  'if err != nil || version != auth.Domain.Version {' 'if err != nil {'
mutate "unknown accepted member allowed" TestRefusals \
  'return nil, "", refuse("accepted: unknown member %q", k)' 'continue'
mutate "unknown extra member allowed" TestRefusals \
  'return nil, "", refuse("accepted.extra: unknown member %q", k)' 'continue'
mutate "transfer method unchecked" TestRefusals \
  'if err != nil || m != "eip3009" {' 'if err != nil {'
mutate "duplicates allowed" TestRefusals \
  'return fmt.Errorf("duplicate member %q", k)' 'seen[k] = true'
mutate "resource url not compared" TestRefusals \
  'if url != cfg.ResourceURL {' 'if url == "" {'
mutate "unknown resource member allowed" TestRefusals \
  'return nil, refuse("resource: unknown member %q", k)' 'continue'
mutate "description unbounded" TestRefusals \
  'if len(s) > maxInfoLen {' 'if false {'
mutate "timeout ceiling unchecked" TestRefusals \
  'if n, err := canonicalJSONInt(mts); err != nil || n < 1 || n > int64(cfg.MaxTimeoutCeiling) {' 'if _, err := canonicalJSONInt(mts); err != nil {'
mutate "checksum unchecked" TestChecksumHandling \
  'if body != lower && body != upper && checksum(a) != s {' 'if false {'
mutate "signature not checked" TestNoPayloadWithoutAGuardedSignature \
  'if err := b.CheckSigned(sig, recovered); err != nil {' 'if false {'
mutate "accepted re-rendered" TestPayloadEchoesAcceptedExactlyAndCarriesTheAuthorization \
  '	return compact, payTo, nil' '	re, _ := json.Marshal(members); return re, payTo, nil'
mutate "authorization.to re-cased" TestPayloadEchoesAcceptedExactlyAndCarriesTheAuthorization \
  '	writeJSONString(&out, payTo)' '	writeJSONString(&out, checksum(auth.To))'

if [ "$fail" -ne 0 ]; then
  echo "FAIL: a mutation survived or did not apply"
  exit 1
fi
echo "PASS: every mutation was killed"

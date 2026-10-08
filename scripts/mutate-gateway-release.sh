#!/usr/bin/env bash
# Mutation check for the gateway's EIP-3009 release path (SPEC-ARC-M3 §4.1.5,
# §6.3). Each mutation removes or weakens one control on the way from an ALLOW
# to a released payload. It MUST be killed by the named tests. A mutation whose
# anchor is not found exactly once is an error, never a skip. The repository
# tree is never written to; a copy is mutated. A mutant that does not compile
# is an error, not a kill.
#
# Excluded as equivalent: a JSON null resource_url decodes to "" and is refused
# by checkResourceURL, so no separate null check exists to mutate.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM
cp -r . "$SCRATCH/repo"
G="$SCRATCH/repo/cmd/arc-gateway"

fail=0
# mutate <name> <file> <test regexp> <from> <to>
mutate() {
  local name="$1" file="$G/$2" want="$3" from="$4" to="$5"
  local orig
  orig=$(cat "$file")
  local n
  n=$(FROM="$from" python3 -I -c 'import os,sys; print(sys.stdin.read().count(os.environ["FROM"]))' < "$file")
  if [ "$n" != "1" ]; then
    echo "ERROR     $name: anchor found $n times"
    fail=1
    return
  fi
  FROM="$from" TO="$to" python3 -I -c 'import os,sys; s=sys.stdin.read(); sys.stdout.write(s.replace(os.environ["FROM"], os.environ["TO"], 1))' < "$file" > "$file.new" && mv "$file.new" "$file"
  if ! (cd "$SCRATCH/repo" && CGO_ENABLED=0 go vet -tags arc ./cmd/arc-gateway/ >/dev/null 2>&1); then
    echo "ERROR     $name: the mutant does not compile"
    fail=1
  elif (cd "$SCRATCH/repo" && CGO_ENABLED=0 go test -tags arc ./cmd/arc-gateway/ -run "$want" >/dev/null 2>&1); then
    echo "SURVIVED  $name (want killed by $want)"
    fail=1
  else
    echo "killed    $name"
  fi
  printf '%s\n' "$orig" > "$file"
}

mutate "requirements not checked before recording" m3.go TestEIP3009BadRequirements \
  'if err := x402v2.Check(m.x402, b, accepted, resource); err != nil {' 'if err := error(nil); err != nil {'
mutate "completion error ignored" m3.go TestEIP3009CompletionFailure \
  'return withheld("the completion record could not be persisted", err)' '_ = err'
mutate "completion skipped" m3.go 'TestEIP3009ReleasesThePayload|TestEIP3009NothingLeaves' \
  'c, err := m.completion(refSeq, p.SHA256)' 'c, err := correlation.Completion{}, error(nil)'
mutate "completion of another payload" m3.go TestEIP3009ReleasesThePayload \
  'c, err := m.completion(refSeq, p.SHA256)' 'c, err := m.completion(refSeq, func() [32]byte { h := p.SHA256; h[0] ^= 1; return h }())'
mutate "signer retried on error" m3.go TestEIP3009UncertainSigningOutcome \
  'sig, err := m.signEIP(ctx, b)' 'sig, err := m.signEIP(ctx, b); if err != nil { sig, err = m.signEIP(ctx, b) }'
mutate "signer error leaks a signature" m3.go TestEIP3009UncertainSigningOutcome \
  'return fmt.Sprintf("AUTHORIZED (log entry %s), but no acceptable signature was produced: %s. "+noRetry,
			locator, firstLine(err.Error()), pid), true' 'return fmt.Sprintf("AUTHORIZED (log entry %s), but no acceptable signature was produced: %s %x. "+noRetry,
			locator, firstLine(err.Error()), sig, pid), true'
mutate "build refusal ignored" m3.go TestEIP3009UncertainSigningOutcome \
  'return withheld("the payload could not be built", err)' 'p.Header = "x"'
mutate "release not reported" server.go TestEIP3009ReleasesThePayload \
  'if rel := s.release; rel != nil {' 'if rel := s.release; rel != nil && false {'
mutate "write failure not reported as unknown" server.go TestEIP3009FailedReplyWrite \
  'if err := reply(result); err != nil {' 'if err := reply(result); err != nil && false {'
mutate "write error swallowed" server.go TestEIP3009FailedReplyWrite \
  '		return err
	}
	return nil
}' '	}
	return nil
}'
mutate "objects admitted as strings" args.go TestEIP3009MalformedObjects \
  'if _, err := strictObject(v); err != nil {' 'if _, err := strictObject(v); err != nil && !isJSONString(v) {'
mutate "object presence not required" args.go TestEIP3009MalformedObjects \
  'if _, ok := tc.Objects[o]; !ok {' 'if _, ok := tc.Objects[o]; !ok && false {'
mutate "resource_url not required by the rail" m3flags.go TestEIP3009RailRefusesWithoutTheApprovedResourceURL \
  'if f.rail == railEIP3009 && cp.ResourceURL == "" {' 'if false {'
mutate "resource_url not validated" capability.go TestCapabilityResourceURL \
  'if err := checkResourceURL(resourceURL); err != nil {' 'if err := error(nil); err != nil {'

exit $fail

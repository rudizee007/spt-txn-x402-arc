# Test vectors

- `reference-vectors.json`: produced by running the public reference
  implementation, `github.com/rudizee007/spt-txn-poc` at commit `149b57f`
  (`pkg/jcs.CanonicalizeRaw` and `internal/intent.Intent.Digest`). The generator
  is `vecgen.go.txt`. To regenerate, copy it to `cmd/zzvecgen/main.go` in a
  checkout of that repository and run `go run ./cmd/zzvecgen`. The random
  vectors are seeded, so the output is reproducible.
- `eip3009-nonce-vectors.json`: computed with Python's `hashlib`, independently of
  the Go code, from the derivation in SPEC-ARC-M3 §4.1.4.

This package does not import the reference. These files are the only link to it.

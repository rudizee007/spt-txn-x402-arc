//go:build arc && cgo

package main

// This build would link C `libsecp256k1` through go-ethereum's crypto package.
// CLAUDE.md forbids C and C++ inside the trust boundary, including via cgo, and
// go-ethereum has an audited pure-Go fallback (decred/dcrd/dcrec/secp256k1)
// that is selected automatically when cgo is off. So build it off:
//
//	CGO_ENABLED=0 go run -tags arc ./cmd/payarc ...
//
// The compile error below is deliberate. It is here rather than in a README
// because a rule written in a README is a rule a build can ignore, and "never
// write a check that a refactor can silently delete" applies to build settings
// as much as to code. Deleting this file to make the error go away is not
// silent.
const _ = payarcRequiresCGO_ENABLED_0_seeThisFile

//go:build arc && cgo

package arcpay

// This package links go-ethereum's crypto, which would pull in C libsecp256k1
// with cgo on. The project forbids C inside the trust boundary, including via
// cgo, and go-ethereum selects an audited pure-Go secp256k1 when cgo is off.
// Build with CGO_ENABLED=0. The compile error is deliberate; see
// cmd/payarc/nocgo.go.
const _ = arcpayRequiresCGO_ENABLED_0_seeThisFile

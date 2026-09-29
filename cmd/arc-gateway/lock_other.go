//go:build arc && !unix

package main

import (
	"fmt"
	"os"

	"github.com/rudizee007/spt-txn-x402-arc/settle/evm/arcpay"
)

// lockFile refuses on a platform without flock: a gateway that cannot hold its
// log and its capability exclusively does not start (SPEC-ARC-GATE §6).
func lockFile(path, holder string) (*os.File, error) {
	return nil, fmt.Errorf("%w: this platform has no flock, so %s cannot be held exclusively", arcpay.ErrUnavailable, holder)
}

//go:build arc && !unix

package arcpay

import "os"

// ownerUID reports no owner where the platform has no uid; the mode check
// still applies.
var ownerUID = func(os.FileInfo) (uint32, bool) { return 0, false }

var effectiveUID = func() uint32 { return 0 }

//go:build arc && !unix

package arcpay

import "os"

// ownerUID reports no owner where the platform has no uid; the mode check
// still applies.
func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }

func effectiveUID() uint32 { return 0 }

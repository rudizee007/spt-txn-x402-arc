//go:build arc && unix

package arcpay

import (
	"os"
	"syscall"
)

// ownerUID is the uid that owns fi. It is a variable so tests can check the
// owner rule for a directory above the one checked.
var ownerUID = func(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// effectiveUID is the uid this process runs as. It is a variable so tests can
// check the owner rule without root.
var effectiveUID = func() uint32 {
	// #nosec G115 -- a uid fits in a uint32, the type the kernel reports.
	return uint32(os.Geteuid())
}

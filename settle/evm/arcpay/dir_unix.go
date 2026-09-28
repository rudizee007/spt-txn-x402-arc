//go:build arc && unix

package arcpay

import (
	"os"
	"syscall"
)

// ownerUID is the uid that owns fi.
func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// effectiveUID is the uid this process runs as.
func effectiveUID() uint32 {
	// #nosec G115 -- a uid fits in a uint32, the type the kernel reports.
	return uint32(os.Geteuid())
}

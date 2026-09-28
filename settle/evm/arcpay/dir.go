//go:build arc

package arcpay

import (
	"fmt"
	"os"
	"path/filepath"
)

// CheckOwnerOnlyDir refuses a directory that is not a directory, that group or
// others can write, or that another user owns. Whoever can write a directory
// can replace the files in it: key files, and the gateway's log, counts and
// locks.
func CheckOwnerOnlyDir(dir string) error {
	dir = filepath.Clean(dir)
	fi, err := os.Stat(dir)
	if err != nil {
		return unavailable(fmt.Errorf("directory %s: %w", dir, err))
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return violation(fmt.Errorf("%s must be a directory that only its owner can write (mode %04o).\n  chmod 700 %s", dir, fi.Mode().Perm(), dir))
	}
	if uid, ok := ownerUID(fi); ok && uid != effectiveUID() {
		return violation(fmt.Errorf("%s must be a directory that only its owner can write: it is owned by uid %d, not uid %d, which runs this process", dir, uid, effectiveUID()))
	}
	return nil
}

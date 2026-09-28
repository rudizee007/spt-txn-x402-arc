//go:build arc

package arcpay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckOwnerOnlyDir refuses a directory that is not a directory, that group or
// others can write (a sticky bit does not change that), or whose owner is
// neither this process's uid nor root. Whoever can write a directory can
// replace the files in it: key files, and the gateway's log, counts and locks.
func CheckOwnerOnlyDir(dir string) error {
	dir = filepath.Clean(dir)
	fi, err := os.Stat(dir)
	if err != nil {
		return unavailable(fmt.Errorf("directory %s: %w", dir, err))
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return violation(fmt.Errorf("%s must be a directory that only its owner can write (mode %04o).\n  chmod 700 %s", dir, fi.Mode().Perm(), dir))
	}
	if uid, ok := ownerUID(fi); ok && uid != effectiveUID() && uid != 0 {
		return violation(fmt.Errorf("%s must be a directory that only its owner can write: it is owned by uid %d, neither uid %d, which runs this process, nor root", dir, uid, effectiveUID()))
	}
	return nil
}

// CheckPrivatePath refuses dir unless no component of its absolute path is a
// symlink, every directory above it is owned by this process's uid or root and
// is not writable by group or others unless its sticky bit is set, and dir
// itself passes CheckOwnerOnlyDir. A directory that another account can rename
// entries in lets that account replace dir, however dir itself is set up.
func CheckPrivatePath(dir string) error {
	abs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return unavailable(fmt.Errorf("directory %s: %w", dir, err))
	}
	vol := filepath.VolumeName(abs)
	cur := vol + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(abs[len(vol):], string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 1 && parts[0] == "" {
		parts = nil // dir is the root directory
	}
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, parts[i])
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return unavailable(fmt.Errorf("directory %s: %w", cur, err))
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return violation(fmt.Errorf("%s is a symlink; name the real path to %s", cur, abs))
		}
		if !fi.IsDir() {
			return violation(fmt.Errorf("%s, on the path to %s, is not a directory", cur, abs))
		}
		if i == len(parts)-1 {
			return CheckOwnerOnlyDir(cur)
		}
		if uid, ok := ownerUID(fi); ok && uid != effectiveUID() && uid != 0 {
			return violation(fmt.Errorf("directory %s, above %s, is owned by uid %d, neither uid %d, which runs this process, nor root", cur, abs, uid, effectiveUID()))
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return violation(fmt.Errorf("directory %s, above %s, can be written by group or others and is not sticky (mode %04o)", cur, abs, fi.Mode().Perm()))
		}
	}
	return nil
}

//go:build arc

package arcpay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxPathLinks bounds the symlinks one path may pass through.
const maxPathLinks = 40

// CheckOwnerOnlyDir refuses a directory that is not a directory, that group or
// others can write (a sticky bit does not change that), or whose owner is
// neither this process's uid nor root. It follows a symlink at dir itself; the
// walk in ResolvePrivatePath judges the last directory from its own lookup.
func CheckOwnerOnlyDir(dir string) error {
	dir = filepath.Clean(dir)
	fi, err := os.Stat(dir)
	if err != nil {
		return unavailable(fmt.Errorf("directory %s: %w", dir, err))
	}
	return ownerOnly(dir, fi)
}

// ownerOnly is the rule for the last directory of a path, applied to fi.
func ownerOnly(dir string, fi os.FileInfo) error {
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return violation(fmt.Errorf("%s must be a directory that only its owner can write (mode %04o).\n  chmod 700 %s", dir, fi.Mode().Perm(), dir))
	}
	if uid, ok := ownerUID(fi); ok && uid != effectiveUID() && uid != 0 {
		return violation(fmt.Errorf("%s must be a directory that only its owner can write: it is owned by uid %d, neither uid %d, which runs this process, nor root", dir, uid, effectiveUID()))
	}
	return nil
}

// CheckPrivatePath reports whether ResolvePrivatePath accepts dir.
func CheckPrivatePath(dir string) error {
	_, err := ResolvePrivatePath(dir)
	return err
}

// ResolvePrivatePath walks the absolute path of dir one component at a time
// from the root and returns the path it resolved. Every directory above the
// last must be owned by this process's uid or root and must not be writable by
// group or others unless its sticky bit is set; the last must pass the
// owner-only rule, judged from the walk's own lookup. A symlink is followed
// only if root owns it; the directory holding it has passed by then, and its
// target is walked in full. Any other symlink, or more than maxPathLinks,
// refuses the path. Files are then opened through the returned path.
func ResolvePrivatePath(dir string) (string, error) { return resolvePath(dir, true) }

// ResolveParentPath is ResolvePrivatePath for a directory that will hold the
// last one: every component, dir included, is judged by the rule for a
// directory above, so a sticky dir is accepted.
func ResolveParentPath(dir string) (string, error) { return resolvePath(dir, false) }

// resolvePath is the walk. lastIsLeaf selects the owner-only rule, rather
// than the rule for a directory above, for the last component.
func resolvePath(dir string, lastIsLeaf bool) (string, error) {
	last := ownerOnly
	if !lastIsLeaf {
		last = func(d string, fi os.FileInfo) error { return aboveRule(d, d, fi) }
	}
	// Every error returns "", never a partly resolved path.
	done := func(p string, err error) (string, error) {
		if err != nil {
			return "", err
		}
		return p, nil
	}
	abs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", unavailable(fmt.Errorf("directory %s: %w", dir, err))
	}
	sep := string(filepath.Separator)
	vol := filepath.VolumeName(abs)
	root := vol + sep
	fi, err := os.Lstat(root)
	if err != nil {
		return "", unavailable(fmt.Errorf("directory %s: %w", root, err))
	}
	pending := splitPath(abs[len(vol):])
	if len(pending) == 0 {
		return done(root, last(root, fi))
	}
	if err := aboveRule(root, abs, fi); err != nil {
		return "", err
	}
	cur, links := root, 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		next := filepath.Join(cur, name)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", unavailable(fmt.Errorf("directory %s: %w", next, err))
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if uid, ok := ownerUID(fi); !ok || uid != 0 {
				return "", violation(fmt.Errorf("%s is a symlink not owned by root; name the real path to %s", next, abs))
			}
			if links++; links > maxPathLinks {
				return "", violation(fmt.Errorf("more than %d symlinks on the path to %s", maxPathLinks, abs))
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", unavailable(fmt.Errorf("symlink %s: %w", next, err))
			}
			// The target replaces the link. cur holds only resolved
			// directories, so a relative target joins it and cleans
			// correctly; an absolute one restarts at the root.
			if !filepath.IsAbs(target) {
				target = filepath.Join(cur, target)
			}
			pending = append(splitPath(filepath.Clean(target)[len(filepath.VolumeName(target)):]), pending...)
			cur = root
			continue
		}
		if !fi.IsDir() {
			return "", violation(fmt.Errorf("%s, on the path to %s, is not a directory", next, abs))
		}
		if len(pending) == 0 {
			return done(next, last(next, fi))
		}
		if err := aboveRule(next, abs, fi); err != nil {
			return "", err
		}
		cur = next
	}
	return done(cur, last(cur, fi))
}

// aboveRule is the rule for a directory above the last one.
func aboveRule(dir, abs string, fi os.FileInfo) error {
	if !fi.IsDir() {
		return violation(fmt.Errorf("%s, on the path to %s, is not a directory", dir, abs))
	}
	if uid, ok := ownerUID(fi); ok && uid != effectiveUID() && uid != 0 {
		return violation(fmt.Errorf("directory %s, above %s, is owned by uid %d, neither uid %d, which runs this process, nor root", dir, abs, uid, effectiveUID()))
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return violation(fmt.Errorf("directory %s, above %s, can be written by group or others and is not sticky (mode %04o)", dir, abs, fi.Mode().Perm()))
	}
	return nil
}

// splitPath splits a cleaned, rooted path into its components.
func splitPath(p string) []string {
	p = strings.Trim(p, string(filepath.Separator))
	if p == "" {
		return nil
	}
	return strings.Split(p, string(filepath.Separator))
}

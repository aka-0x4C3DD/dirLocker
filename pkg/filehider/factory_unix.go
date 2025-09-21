//go:build !windows

package filehider

// newPlatformFileHider creates a Unix-specific file hider
func newPlatformFileHider() (FileHider, error) {
	return NewUnixFileHider()
}

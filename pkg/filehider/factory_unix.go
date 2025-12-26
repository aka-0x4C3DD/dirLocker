//go:build !windows

package filehider

// newPlatformFileHider creates a Unix-specific file hider
func newPlatformFileHider() (FileHider, error) {
	return NewUnixFileHider()
}

// newPlatformFileHiderWithRoot creates a Unix-specific file hider with a custom root
func newPlatformFileHiderWithRoot(rootDir string) (FileHider, error) {
	return newUnixFileHiderWithRoot(rootDir)
}

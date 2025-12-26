//go:build windows

package filehider

// newPlatformFileHider creates a Windows-specific file hider
func newPlatformFileHider() (FileHider, error) {
	return NewWindowsFileHider()
}

// newPlatformFileHiderWithRoot creates a Windows-specific file hider with a custom root
func newPlatformFileHiderWithRoot(rootDir string) (FileHider, error) {
	return newWindowsFileHiderWithRoot(rootDir)
}

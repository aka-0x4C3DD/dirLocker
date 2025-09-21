//go:build windows

package filehider

// newPlatformFileHider creates a Windows-specific file hider
func newPlatformFileHider() (FileHider, error) {
	return NewWindowsFileHider()
}

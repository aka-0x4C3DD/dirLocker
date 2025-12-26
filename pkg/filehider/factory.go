package filehider

// NewFileHider creates a new FileHider instance appropriate for the current platform
func NewFileHider() (FileHider, error) {
	return newPlatformFileHider()
}

// NewFileHiderForTesting creates a new FileHider instance with a custom root directory for testing
func NewFileHiderForTesting(rootDir string) (FileHider, error) {
	return newPlatformFileHiderWithRoot(rootDir)
}

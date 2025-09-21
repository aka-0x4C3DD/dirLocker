package filehider

// NewFileHider creates a new FileHider instance appropriate for the current platform
func NewFileHider() (FileHider, error) {
	return newPlatformFileHider()
}

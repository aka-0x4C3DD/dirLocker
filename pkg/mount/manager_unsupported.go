//go:build !windows && !darwin && !linux
// +build !windows,!darwin,!linux

package mount

import (
	"fmt"
	"runtime"

	"dirLocker/pkg/logging"
)

// createPlatformMounter creates a platform-specific mounter
func createPlatformMounter(logger *logging.Logger) (Mounter, error) {
	return nil, &MountError{
		Code:    MountErrorUnsupported,
		Message: fmt.Sprintf("mounting not supported on platform: %s", runtime.GOOS),
	}
}

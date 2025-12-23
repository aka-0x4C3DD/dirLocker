//go:build cgo && linux
// +build cgo,linux

package mount

import (
	"dirLocker/pkg/logging"
)

// createPlatformMounter creates a platform-specific mounter
func createPlatformMounter(logger *logging.Logger) (Mounter, error) {
	return NewLinuxMounter(logger)
}

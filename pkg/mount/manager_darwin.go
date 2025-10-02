//go:build darwin
// +build darwin

package mount

import (
	"dirLocker/pkg/logging"
)

// createPlatformMounter creates a platform-specific mounter
func createPlatformMounter(logger *logging.Logger) (Mounter, error) {
	return NewDarwinMounter(logger)
}

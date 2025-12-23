//go:build cgo && windows
// +build cgo,windows

package mount

import (
	"dirLocker/pkg/logging"
)

// createPlatformMounter creates a platform-specific mounter
func createPlatformMounter(logger *logging.Logger) (Mounter, error) {
	return NewWindowsMounter(logger)
}

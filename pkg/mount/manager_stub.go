//go:build !cgo
// +build !cgo

package mount

import (
	"dirLocker/pkg/logging"
)

// createPlatformMounter creates a stub mounter when CGO is disabled
func createPlatformMounter(logger *logging.Logger) (Mounter, error) {
	return &StubMounter{logger: logger}, nil
}

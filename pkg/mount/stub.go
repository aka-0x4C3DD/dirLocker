//go:build !cgo
// +build !cgo

package mount

import (
	"context"

	"dirLocker/pkg/logging"
)

// StubMounter provides a stub implementation when mounting is not available
type StubMounter struct {
	logger *logging.Logger
}

// Mount returns an error indicating mounting is not available
func (s *StubMounter) Mount(ctx context.Context, vault VaultInterface, options *MountOptions) (*MountInfo, error) {
	return nil, &MountError{
		Code:    MountErrorUnsupported,
		Message: "mounting not available (CGO disabled)",
	}
}

// Unmount returns an error indicating mounting is not available
func (s *StubMounter) Unmount(ctx context.Context, mountPoint string) error {
	return &MountError{
		Code:    MountErrorUnsupported,
		Message: "mounting not available (CGO disabled)",
	}
}

// IsMounted always returns false
func (s *StubMounter) IsMounted(mountPoint string) (bool, error) {
	return false, nil
}

// ListMounts returns an empty list
func (s *StubMounter) ListMounts() ([]*MountInfo, error) {
	return []*MountInfo{}, nil
}

// GetMountInfo returns an error
func (s *StubMounter) GetMountInfo(mountPoint string) (*MountInfo, error) {
	return nil, &MountError{
		Code:    MountErrorMountPointNotFound,
		Message: "mounting not available (CGO disabled)",
	}
}

// IsSupported always returns false
func (s *StubMounter) IsSupported() bool {
	return false
}

// GetRequiredDrivers returns an empty list
func (s *StubMounter) GetRequiredDrivers() []string {
	return []string{}
}

// CheckDrivers returns an error
func (s *StubMounter) CheckDrivers() error {
	return &MountError{
		Code:    MountErrorUnsupported,
		Message: "mounting not available (CGO disabled)",
	}
}

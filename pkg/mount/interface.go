package mount

import (
	"context"
	"time"
)

// MountOptions contains configuration for mounting a vault
type MountOptions struct {
	MountPoint   string        // Path where vault should be mounted
	ReadOnly     bool          // Mount as read-only
	AllowOther   bool          // Allow other users to access mount
	Timeout      time.Duration // Operation timeout
	Debug        bool          // Enable debug logging
	CacheTimeout time.Duration // File attribute cache timeout
	MaxReadAhead int           // Maximum read-ahead size
}

// MountInfo contains information about a mounted vault
type MountInfo struct {
	VaultPath  string    // Path to the vault file
	MountPoint string    // Where the vault is mounted
	MountedAt  time.Time // When the vault was mounted
	ReadOnly   bool      // Whether mounted read-only
	FileSystem string    // Filesystem type (fuse, dokany, winfsp)
	ProcessID  int       // PID of mount process
}

// VaultInterface represents the minimal interface needed for mounting
type VaultInterface interface {
	GetPath() string
	GetPassword() string
	UpdateLastUsed()
}

// Mounter interface defines the contract for filesystem mounting implementations
type Mounter interface {
	// Mount mounts a vault at the specified mount point
	Mount(ctx context.Context, vault VaultInterface, options *MountOptions) (*MountInfo, error)

	// Unmount unmounts a vault from the specified mount point
	Unmount(ctx context.Context, mountPoint string) error

	// IsMounted checks if a vault is currently mounted at the given path
	IsMounted(mountPoint string) (bool, error)

	// ListMounts returns all currently mounted vaults
	ListMounts() ([]*MountInfo, error)

	// GetMountInfo returns information about a specific mount
	GetMountInfo(mountPoint string) (*MountInfo, error)

	// IsSupported returns true if mounting is supported on this platform
	IsSupported() bool

	// GetRequiredDrivers returns a list of required drivers/packages for mounting
	GetRequiredDrivers() []string

	// CheckDrivers verifies that required drivers are installed
	CheckDrivers() error
}

// MountError represents mounting-related errors
type MountError struct {
	Code    MountErrorCode
	Message string
	Cause   error
}

// MountErrorCode represents different types of mount errors
type MountErrorCode int

const (
	MountErrorUnknown MountErrorCode = iota
	MountErrorDriverNotFound
	MountErrorPermissionDenied
	MountErrorMountPointInUse
	MountErrorMountPointNotFound
	MountErrorVaultNotOpen
	MountErrorTimeout
	MountErrorUnsupported
	MountErrorInvalidOptions
)

func (e *MountError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// DefaultMountOptions returns default mounting options
func DefaultMountOptions() *MountOptions {
	return &MountOptions{
		ReadOnly:     false,
		AllowOther:   false,
		Timeout:      30 * time.Second,
		Debug:        false,
		CacheTimeout: 1 * time.Second,
		MaxReadAhead: 128 * 1024, // 128KB
	}
}

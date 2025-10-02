package mount

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"dirLocker/pkg/logging"
)

// Manager manages vault mounting operations across platforms
type Manager struct {
	mounter      Mounter
	logger       *logging.Logger
	activeMounts map[string]*MountInfo
	mutex        sync.RWMutex
}

// NewManager creates a new mount manager for the current platform
func NewManager(logger *logging.Logger) (*Manager, error) {
	mounter, err := createPlatformMounter(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform mounter: %w", err)
	}

	manager := &Manager{
		mounter:      mounter,
		logger:       logger,
		activeMounts: make(map[string]*MountInfo),
	}

	// Load existing mounts
	if err := manager.loadExistingMounts(); err != nil {
		logger.Warn("Failed to load existing mounts", "error", err)
	}

	return manager, nil
}

// Mount mounts a vault at the specified mount point
func (m *Manager) Mount(ctx context.Context, vault VaultInterface, options *MountOptions) (*MountInfo, error) {
	if options == nil {
		options = DefaultMountOptions()
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if mount point is already in use
	if _, exists := m.activeMounts[options.MountPoint]; exists {
		return nil, &MountError{
			Code:    MountErrorMountPointInUse,
			Message: fmt.Sprintf("mount point already in use: %s", options.MountPoint),
		}
	}

	// Check if mounter is supported
	if !m.mounter.IsSupported() {
		return nil, &MountError{
			Code:    MountErrorUnsupported,
			Message: "mounting not supported on this system",
		}
	}

	// Check required drivers
	if err := m.mounter.CheckDrivers(); err != nil {
		return nil, &MountError{
			Code:    MountErrorDriverNotFound,
			Message: "required drivers not found",
			Cause:   err,
		}
	}

	m.logger.Info("Mounting vault", "vault_path", vault.GetPath(), "mount_point", options.MountPoint)

	// Perform the mount
	mountInfo, err := m.mounter.Mount(ctx, vault, options)
	if err != nil {
		m.logger.Error("Failed to mount vault", "error", err, "vault_path", vault.GetPath())
		return nil, err
	}

	// Track the mount
	m.activeMounts[options.MountPoint] = mountInfo
	m.logger.Info("Successfully mounted vault", "vault_path", vault.GetPath(), "mount_point", options.MountPoint)

	return mountInfo, nil
}

// Unmount unmounts a vault from the specified mount point
func (m *Manager) Unmount(ctx context.Context, mountPoint string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	mountInfo, exists := m.activeMounts[mountPoint]
	if !exists {
		return &MountError{
			Code:    MountErrorMountPointNotFound,
			Message: fmt.Sprintf("no mount found at: %s", mountPoint),
		}
	}

	m.logger.Info("Unmounting vault", "mount_point", mountPoint, "vault_path", mountInfo.VaultPath)

	// Perform the unmount
	if err := m.mounter.Unmount(ctx, mountPoint); err != nil {
		m.logger.Error("Failed to unmount vault", "error", err, "mount_point", mountPoint)
		return err
	}

	// Remove from tracking
	delete(m.activeMounts, mountPoint)
	m.logger.Info("Successfully unmounted vault", "mount_point", mountPoint)

	return nil
}

// UnmountAll unmounts all currently mounted vaults
func (m *Manager) UnmountAll(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var errors []error
	for mountPoint := range m.activeMounts {
		if err := m.mounter.Unmount(ctx, mountPoint); err != nil {
			m.logger.Error("Failed to unmount vault during cleanup", "error", err, "mount_point", mountPoint)
			errors = append(errors, err)
		} else {
			m.logger.Info("Unmounted vault during cleanup", "mount_point", mountPoint)
		}
	}

	// Clear all mounts regardless of errors
	m.activeMounts = make(map[string]*MountInfo)

	if len(errors) > 0 {
		return fmt.Errorf("failed to unmount %d vaults: %v", len(errors), errors)
	}

	return nil
}

// IsMounted checks if a vault is currently mounted at the given path
func (m *Manager) IsMounted(mountPoint string) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check our internal tracking first
	if _, exists := m.activeMounts[mountPoint]; exists {
		return true, nil
	}

	// Check with the platform mounter
	return m.mounter.IsMounted(mountPoint)
}

// ListMounts returns all currently mounted vaults
func (m *Manager) ListMounts() ([]*MountInfo, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	mounts := make([]*MountInfo, 0, len(m.activeMounts))
	for _, mountInfo := range m.activeMounts {
		mounts = append(mounts, mountInfo)
	}

	return mounts, nil
}

// GetMountInfo returns information about a specific mount
func (m *Manager) GetMountInfo(mountPoint string) (*MountInfo, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if mountInfo, exists := m.activeMounts[mountPoint]; exists {
		return mountInfo, nil
	}

	return nil, &MountError{
		Code:    MountErrorMountPointNotFound,
		Message: fmt.Sprintf("no mount found at: %s", mountPoint),
	}
}

// IsSupported returns true if mounting is supported on this platform
func (m *Manager) IsSupported() bool {
	return m.mounter.IsSupported()
}

// GetRequiredDrivers returns a list of required drivers/packages for mounting
func (m *Manager) GetRequiredDrivers() []string {
	return m.mounter.GetRequiredDrivers()
}

// CheckDrivers verifies that required drivers are installed
func (m *Manager) CheckDrivers() error {
	return m.mounter.CheckDrivers()
}

// GetTroubleshootingInfo returns platform-specific troubleshooting information
func (m *Manager) GetTroubleshootingInfo() string {
	switch runtime.GOOS {
	case "windows":
		return `Mount failed on Windows. Common solutions:

1. Install Dokany or WinFSP:
   • Download from: https://github.com/dokan-dev/dokany/releases
   • Or: https://github.com/billziss-gh/winfsp/releases

2. Run as Administrator:
   • Right-click dirLocker and select "Run as administrator"

3. Check drive letter availability:
   • Make sure the selected drive letter is not in use

4. Antivirus software:
   • Some antivirus programs block filesystem drivers
   • Add dirLocker to your antivirus whitelist`

	case "darwin":
		return `Mount failed on macOS. Common solutions:

1. Install macFUSE:
   • Download from: https://osxfuse.github.io/
   • Follow installation instructions and restart

2. Enable System Extension:
   • Go to System Preferences > Security & Privacy
   • Allow macFUSE system extension if prompted

3. Check mount point permissions:
   • Make sure you have write access to the mount directory
   • Try using /tmp/vault_mount as a test location

4. Gatekeeper issues:
   • You may need to allow dirLocker in Security & Privacy settings`

	default: // Linux
		return `Mount failed on Linux. Common solutions:

1. Install FUSE:
   • Ubuntu/Debian: sudo apt install fuse
   • CentOS/RHEL: sudo yum install fuse
   • Arch: sudo pacman -S fuse2

2. Add user to fuse group:
   • sudo usermod -a -G fuse $USER
   • Log out and back in

3. Check mount point permissions:
   • Make sure you have write access to the mount directory
   • Try using /tmp/vault_mount as a test location

4. Load fuse module:
   • sudo modprobe fuse`
	}
}

// loadExistingMounts attempts to discover and track existing mounts
func (m *Manager) loadExistingMounts() error {
	existingMounts, err := m.mounter.ListMounts()
	if err != nil {
		return err
	}

	for _, mountInfo := range existingMounts {
		m.activeMounts[mountInfo.MountPoint] = mountInfo
	}

	m.logger.Info("Loaded existing mounts", "count", len(existingMounts))
	return nil
}

// StartCleanupTimer starts a timer to clean up stale mounts
func (m *Manager) StartCleanupTimer() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			m.cleanupStaleMounts()
		}
	}()
}

// cleanupStaleMounts removes mounts that are no longer active
func (m *Manager) cleanupStaleMounts() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var toRemove []string
	for mountPoint := range m.activeMounts {
		if mounted, err := m.mounter.IsMounted(mountPoint); err != nil || !mounted {
			toRemove = append(toRemove, mountPoint)
		}
	}

	for _, mountPoint := range toRemove {
		delete(m.activeMounts, mountPoint)
		m.logger.Info("Cleaned up stale mount", "mount_point", mountPoint)
	}
}

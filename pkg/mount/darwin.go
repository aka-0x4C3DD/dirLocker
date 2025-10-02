//go:build darwin
// +build darwin

package mount

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dirLocker/pkg/logging"
)

// MacOSMounter implements mounting for macOS using macFUSE
type MacOSMounter struct {
	logger       *logging.Logger
	mountProcess map[string]*os.Process
}

// NewDarwinMounter creates a new macOS mounter
func NewDarwinMounter(logger *logging.Logger) (*MacOSMounter, error) {
	mounter := &MacOSMounter{
		logger:       logger,
		mountProcess: make(map[string]*os.Process),
	}

	// Check if macFUSE is available
	if !mounter.isMacFUSEAvailable() {
		return nil, &MountError{
			Code:    MountErrorDriverNotFound,
			Message: "macFUSE is not installed or not available",
		}
	}

	logger.Info("Using macFUSE for macOS mounting")
	return mounter, nil
}

// Mount mounts a vault using macFUSE
func (m *MacOSMounter) Mount(ctx context.Context, vault VaultInterface, options *MountOptions) (*MountInfo, error) {
	// Validate and prepare mount point
	if err := m.prepareMountPoint(options.MountPoint); err != nil {
		return nil, &MountError{
			Code:    MountErrorInvalidOptions,
			Message: fmt.Sprintf("invalid mount point: %s", options.MountPoint),
			Cause:   err,
		}
	}

	// Check if mount point is already in use
	if m.isMountPointInUse(options.MountPoint) {
		return nil, &MountError{
			Code:    MountErrorMountPointInUse,
			Message: fmt.Sprintf("mount point already in use: %s", options.MountPoint),
		}
	}

	m.logger.Info("Starting macOS mount process", "mount_point", options.MountPoint)

	// Create FUSE mount command
	cmd := m.createFUSECommand(vault, options)

	// Set up process attributes for proper cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // Create new process group for easier cleanup
	}

	// Start the mount process
	if err := cmd.Start(); err != nil {
		return nil, &MountError{
			Code:    MountErrorTimeout,
			Message: "failed to start FUSE mount process",
			Cause:   err,
		}
	}

	// Wait for mount to be ready with timeout
	mountReady := make(chan bool, 1)
	go func() {
		for i := 0; i < 30; i++ { // Wait up to 30 seconds
			if m.isMountPointMounted(options.MountPoint) {
				mountReady <- true
				return
			}
			time.Sleep(1 * time.Second)
		}
		mountReady <- false
	}()

	select {
	case ready := <-mountReady:
		if !ready {
			cmd.Process.Kill()
			return nil, &MountError{
				Code:    MountErrorTimeout,
				Message: "mount operation timed out",
			}
		}
	case <-ctx.Done():
		cmd.Process.Kill()
		return nil, &MountError{
			Code:    MountErrorTimeout,
			Message: "mount operation cancelled",
			Cause:   ctx.Err(),
		}
	}

	// Track the mount process
	m.mountProcess[options.MountPoint] = cmd.Process

	mountInfo := &MountInfo{
		VaultPath:  vault.GetPath(),
		MountPoint: options.MountPoint,
		MountedAt:  time.Now(),
		ReadOnly:   options.ReadOnly,
		FileSystem: "macfuse",
		ProcessID:  cmd.Process.Pid,
	}

	m.logger.Info("Successfully mounted vault on macOS", "mount_point", options.MountPoint, "pid", cmd.Process.Pid)
	return mountInfo, nil
}

// Unmount unmounts a vault from macOS
func (m *MacOSMounter) Unmount(ctx context.Context, mountPoint string) error {
	m.logger.Info("Unmounting macOS filesystem", "mount_point", mountPoint)

	// Try graceful unmount first
	if err := m.gracefulUnmount(mountPoint); err != nil {
		m.logger.Warn("Graceful unmount failed, trying force unmount", "error", err, "mount_point", mountPoint)
		if err := m.forceUnmount(mountPoint); err != nil {
			return &MountError{
				Code:    MountErrorTimeout,
				Message: "failed to unmount filesystem",
				Cause:   err,
			}
		}
	}

	// Clean up process tracking
	if process, exists := m.mountProcess[mountPoint]; exists {
		// Send SIGTERM to the process group
		if err := syscall.Kill(-process.Pid, syscall.SIGTERM); err != nil {
			m.logger.Warn("Failed to terminate mount process", "error", err, "mount_point", mountPoint)
		}
		delete(m.mountProcess, mountPoint)
	}

	// Verify unmount was successful
	if m.isMountPointMounted(mountPoint) {
		return &MountError{
			Code:    MountErrorTimeout,
			Message: "filesystem still appears to be mounted after unmount attempt",
		}
	}

	m.logger.Info("Successfully unmounted filesystem", "mount_point", mountPoint)
	return nil
}

// IsMounted checks if a mount point is currently mounted
func (m *MacOSMounter) IsMounted(mountPoint string) (bool, error) {
	return m.isMountPointMounted(mountPoint), nil
}

// ListMounts returns all currently mounted filesystems (limited to our mounts)
func (m *MacOSMounter) ListMounts() ([]*MountInfo, error) {
	var mounts []*MountInfo

	for mountPoint, process := range m.mountProcess {
		// Check if process is still running and mount point is active
		if m.isProcessRunning(process) && m.isMountPointMounted(mountPoint) {
			mounts = append(mounts, &MountInfo{
				MountPoint: mountPoint,
				FileSystem: "macfuse",
				ProcessID:  process.Pid,
				MountedAt:  time.Now(), // We don't track exact mount time
			})
		}
	}

	return mounts, nil
}

// GetMountInfo returns information about a specific mount
func (m *MacOSMounter) GetMountInfo(mountPoint string) (*MountInfo, error) {
	if process, exists := m.mountProcess[mountPoint]; exists {
		if m.isProcessRunning(process) && m.isMountPointMounted(mountPoint) {
			return &MountInfo{
				MountPoint: mountPoint,
				FileSystem: "macfuse",
				ProcessID:  process.Pid,
				MountedAt:  time.Now(),
			}, nil
		}
	}

	return nil, &MountError{
		Code:    MountErrorMountPointNotFound,
		Message: fmt.Sprintf("no mount found at %s", mountPoint),
	}
}

// IsSupported returns true if macFUSE mounting is supported
func (m *MacOSMounter) IsSupported() bool {
	return m.isMacFUSEAvailable()
}

// GetRequiredDrivers returns required macOS drivers
func (m *MacOSMounter) GetRequiredDrivers() []string {
	return []string{"macFUSE"}
}

// CheckDrivers verifies that required drivers are installed
func (m *MacOSMounter) CheckDrivers() error {
	if !m.isMacFUSEAvailable() {
		return &MountError{
			Code:    MountErrorDriverNotFound,
			Message: "macFUSE is not installed or not available",
		}
	}
	return nil
}

// Helper methods

func (m *MacOSMounter) isMacFUSEAvailable() bool {
	// Check for macFUSE installation
	macfusePaths := []string{
		"/Library/Frameworks/macFUSE.framework",
		"/System/Library/Extensions/macfuse.kext",
		"/Library/Extensions/macfuse.kext",
		"/usr/local/lib/libfuse.dylib",
	}

	for _, path := range macfusePaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check if FUSE is available via pkg-config
	cmd := exec.Command("pkg-config", "--exists", "fuse")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

func (m *MacOSMounter) prepareMountPoint(mountPoint string) error {
	// Ensure mount point is an absolute path
	if !filepath.IsAbs(mountPoint) {
		return fmt.Errorf("mount point must be an absolute path: %s", mountPoint)
	}

	// Create mount point directory if it doesn't exist
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point directory: %w", err)
	}

	// Check if directory is empty
	entries, err := os.ReadDir(mountPoint)
	if err != nil {
		return fmt.Errorf("failed to read mount point directory: %w", err)
	}

	if len(entries) > 0 {
		return fmt.Errorf("mount point directory is not empty: %s", mountPoint)
	}

	return nil
}

func (m *MacOSMounter) isMountPointInUse(mountPoint string) bool {
	// Check if already mounted by looking at mount table
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, mountPoint) {
			return true
		}
	}

	return false
}

func (m *MacOSMounter) isMountPointMounted(mountPoint string) bool {
	// Check if mount point is mounted by examining /proc/mounts equivalent
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == mountPoint {
			return true
		}
	}

	return false
}

func (m *MacOSMounter) createFUSECommand(vault VaultInterface, options *MountOptions) *exec.Cmd {
	// This would create a command to run our FUSE filesystem implementation
	// For now, this is a placeholder that would need a proper FUSE implementation
	args := []string{
		"mount",
		"--vault", vault.GetPath(),
		"--mountpoint", options.MountPoint,
	}

	if options.ReadOnly {
		args = append(args, "--readonly")
	}

	if options.AllowOther {
		args = append(args, "--allow-other")
	}

	if options.Debug {
		args = append(args, "--debug")
	}

	// Add FUSE-specific options
	args = append(args, "--fuse-option", "volname=dirLocker Vault")
	args = append(args, "--fuse-option", "local")
	args = append(args, "--fuse-option", "noappledouble")

	if options.CacheTimeout > 0 {
		timeout := int(options.CacheTimeout.Seconds())
		args = append(args, "--fuse-option", fmt.Sprintf("attr_timeout=%d", timeout))
		args = append(args, "--fuse-option", fmt.Sprintf("entry_timeout=%d", timeout))
	}

	// This would be the path to our FUSE filesystem implementation
	return exec.Command("dirlocker-fuse", args...)
}

func (m *MacOSMounter) gracefulUnmount(mountPoint string) error {
	// Try unmount command first
	cmd := exec.Command("umount", mountPoint)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("umount failed: %w", err)
	}

	// Wait a moment for unmount to complete
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (m *MacOSMounter) forceUnmount(mountPoint string) error {
	// Force unmount
	cmd := exec.Command("umount", "-f", mountPoint)
	if err := cmd.Run(); err != nil {
		// Try diskutil as last resort
		cmd = exec.Command("diskutil", "unmount", "force", mountPoint)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("force unmount failed: %w", err)
		}
	}

	// Wait for unmount to complete
	time.Sleep(1 * time.Second)
	return nil
}

func (m *MacOSMounter) isProcessRunning(process *os.Process) bool {
	if process == nil {
		return false
	}

	// Check if process is still running by sending signal 0
	err := process.Signal(syscall.Signal(0))
	return err == nil
}

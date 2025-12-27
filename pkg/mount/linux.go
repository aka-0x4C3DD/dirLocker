//go:build linux
// +build linux

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

// LinuxMounter implements mounting for Linux using FUSE
type LinuxMounter struct {
	logger       *logging.Logger
	mountProcess map[string]*os.Process
}

// NewLinuxMounter creates a new Linux mounter
func NewLinuxMounter(logger *logging.Logger) (*LinuxMounter, error) {
	mounter := &LinuxMounter{
		logger:       logger,
		mountProcess: make(map[string]*os.Process),
	}

	// Check if FUSE is available
	if !mounter.isFUSEAvailable() {
		return nil, &MountError{
			Code:    MountErrorDriverNotFound,
			Message: "FUSE is not installed or not available",
		}
	}

	logger.Info("Using FUSE for Linux mounting")
	return mounter, nil
}

// Mount mounts a vault using FUSE on Linux
func (l *LinuxMounter) Mount(ctx context.Context, vault VaultInterface, options *MountOptions) (*MountInfo, error) {
	// Validate and prepare mount point
	if err := l.prepareMountPoint(options.MountPoint); err != nil {
		return nil, &MountError{
			Code:    MountErrorInvalidOptions,
			Message: fmt.Sprintf("invalid mount point: %s", options.MountPoint),
			Cause:   err,
		}
	}

	// Check if mount point is already in use
	if l.isMountPointInUse(options.MountPoint) {
		return nil, &MountError{
			Code:    MountErrorMountPointInUse,
			Message: fmt.Sprintf("mount point already in use: %s", options.MountPoint),
		}
	}

	// Check user permissions for FUSE
	if err := l.checkFUSEPermissions(); err != nil {
		return nil, &MountError{
			Code:    MountErrorPermissionDenied,
			Message: "insufficient permissions for FUSE mounting",
			Cause:   err,
		}
	}

	l.logger.Info("Starting Linux FUSE mount process", "mount_point", options.MountPoint)

	// Create FUSE mount command
	cmd := l.createFUSECommand(vault, options)

	// Set up process attributes for proper cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // Create new process group for easier cleanup
	}

	// Forward stdout and stderr to capture logs from the helper
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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
			if l.isMountPointMounted(options.MountPoint) {
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
	l.mountProcess[options.MountPoint] = cmd.Process

	mountInfo := &MountInfo{
		VaultPath:  vault.GetPath(),
		MountPoint: options.MountPoint,
		MountedAt:  time.Now(),
		ReadOnly:   options.ReadOnly,
		FileSystem: "fuse",
		ProcessID:  cmd.Process.Pid,
	}

	l.logger.Info("Successfully mounted vault on Linux", "mount_point", options.MountPoint, "pid", cmd.Process.Pid)
	return mountInfo, nil
}

// Unmount unmounts a vault from Linux
func (l *LinuxMounter) Unmount(ctx context.Context, mountPoint string) error {
	l.logger.Info("Unmounting Linux FUSE filesystem", "mount_point", mountPoint)

	// Try graceful unmount first
	if err := l.gracefulUnmount(mountPoint); err != nil {
		l.logger.Warn("Graceful unmount failed, trying force unmount", "error", err, "mount_point", mountPoint)
		if err := l.forceUnmount(mountPoint); err != nil {
			return &MountError{
				Code:    MountErrorTimeout,
				Message: "failed to unmount filesystem",
				Cause:   err,
			}
		}
	}

	// Clean up process tracking
	if process, exists := l.mountProcess[mountPoint]; exists {
		// Send SIGTERM to the process group
		if err := syscall.Kill(-process.Pid, syscall.SIGTERM); err != nil {
			l.logger.Warn("Failed to terminate mount process", "error", err, "mount_point", mountPoint)
		}
		delete(l.mountProcess, mountPoint)
	}

	// Verify unmount was successful
	if l.isMountPointMounted(mountPoint) {
		return &MountError{
			Code:    MountErrorTimeout,
			Message: "filesystem still appears to be mounted after unmount attempt",
		}
	}

	l.logger.Info("Successfully unmounted filesystem", "mount_point", mountPoint)
	return nil
}

// IsMounted checks if a mount point is currently mounted
func (l *LinuxMounter) IsMounted(mountPoint string) (bool, error) {
	return l.isMountPointMounted(mountPoint), nil
}

// ListMounts returns all currently mounted filesystems (limited to our mounts)
func (l *LinuxMounter) ListMounts() ([]*MountInfo, error) {
	var mounts []*MountInfo

	for mountPoint, process := range l.mountProcess {
		// Check if process is still running and mount point is active
		if l.isProcessRunning(process) && l.isMountPointMounted(mountPoint) {
			mounts = append(mounts, &MountInfo{
				MountPoint: mountPoint,
				FileSystem: "fuse",
				ProcessID:  process.Pid,
				MountedAt:  time.Now(), // We don't track exact mount time
			})
		}
	}

	return mounts, nil
}

// GetMountInfo returns information about a specific mount
func (l *LinuxMounter) GetMountInfo(mountPoint string) (*MountInfo, error) {
	if process, exists := l.mountProcess[mountPoint]; exists {
		if l.isProcessRunning(process) && l.isMountPointMounted(mountPoint) {
			return &MountInfo{
				MountPoint: mountPoint,
				FileSystem: "fuse",
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

// IsSupported returns true if FUSE mounting is supported
func (l *LinuxMounter) IsSupported() bool {
	return l.isFUSEAvailable()
}

// GetRequiredDrivers returns required Linux packages
func (l *LinuxMounter) GetRequiredDrivers() []string {
	return []string{"fuse", "libfuse2", "libfuse3"}
}

// CheckDrivers verifies that required drivers are installed
func (l *LinuxMounter) CheckDrivers() error {
	if !l.isFUSEAvailable() {
		return &MountError{
			Code:    MountErrorDriverNotFound,
			Message: "FUSE is not installed or not available",
		}
	}

	if err := l.checkFUSEPermissions(); err != nil {
		return &MountError{
			Code:    MountErrorPermissionDenied,
			Message: "insufficient permissions for FUSE mounting",
			Cause:   err,
		}
	}

	return nil
}

// Helper methods

func (l *LinuxMounter) isFUSEAvailable() bool {
	// Check if fusermount3 or fusermount is available in PATH
	// This is required for hanwen/go-fuse and most FUSE implementations
	_, err3 := exec.LookPath("fusermount3")
	_, err := exec.LookPath("fusermount")
	if err3 != nil && err != nil {
		return false
	}

	// Check for FUSE kernel module
	if _, err := os.Stat("/dev/fuse"); err == nil {
		return true
	}

	// Check if FUSE module can be loaded
	cmd := exec.Command("modprobe", "-n", "fuse")
	if err := cmd.Run(); err == nil {
		return true
	}

	// Check for FUSE libraries
	fusePaths := []string{
		"/usr/lib/libfuse.so",
		"/usr/lib/x86_64-linux-gnu/libfuse.so",
		"/usr/lib64/libfuse.so",
		"/lib/libfuse.so",
	}

	for _, path := range fusePaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check if FUSE is available via pkg-config
	cmd = exec.Command("pkg-config", "--exists", "fuse")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

func (l *LinuxMounter) checkFUSEPermissions() error {
	// Check if user is in fuse group
	cmd := exec.Command("groups")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check user groups: %w", err)
	}

	groups := strings.Fields(string(output))
	for _, group := range groups {
		if group == "fuse" {
			return nil // User is in fuse group
		}
	}

	// Check if /dev/fuse is accessible
	if _, err := os.Stat("/dev/fuse"); err != nil {
		return fmt.Errorf("FUSE device not accessible: %w", err)
	}

	// Check if we can access /dev/fuse
	file, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot access FUSE device (try adding user to fuse group): %w", err)
	}
	file.Close()

	return nil
}

func (l *LinuxMounter) prepareMountPoint(mountPoint string) error {
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

func (l *LinuxMounter) isMountPointInUse(mountPoint string) bool {
	return l.isMountPointMounted(mountPoint)
}

func (l *LinuxMounter) isMountPointMounted(mountPoint string) bool {
	// Check /proc/mounts for the mount point
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer file.Close()

	// Read mount table
	content := make([]byte, 4096)
	n, err := file.Read(content)
	if err != nil {
		return false
	}

	lines := strings.Split(string(content[:n]), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == mountPoint {
			return true
		}
	}

	return false
}

func (l *LinuxMounter) createFUSECommand(vault VaultInterface, options *MountOptions) *exec.Cmd {
	// Create command to run our FUSE filesystem implementation via helper
	exePath := options.ExecutablePath
	var err error

	if exePath == "" {
		exePath, err = os.Executable()
		if err != nil {
			l.logger.Error("Failed to get executable path", "error", err)
			exePath = "dirlocker"
		}

		// If we are running tests, the executable will be the test binary (e.g., .../tests.test)
		// In this case, we implemented a fallback to look for the "dirlocker" binary in PATH
		if strings.HasSuffix(exePath, ".test") || strings.Contains(exePath, "go-build") {
			l.logger.Info("Running in test mode, using 'dirlocker' from PATH instead of current executable", "current_exe", exePath)
			exePath = "dirlocker"
		}
	}

	args := []string{
		"mount-helper", "fuse",
		"--vault", vault.GetPath(),
		"--mountpoint", options.MountPoint,
		"--password", vault.GetPassword(),
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

	// Add FUSE-specific options as individual flags
	args = append(args, "--fuse-option", "fsname=dirLocker")
	args = append(args, "--fuse-option", "subtype=vault")

	if options.CacheTimeout > 0 {
		timeout := int(options.CacheTimeout.Seconds())
		args = append(args, "--fuse-option", fmt.Sprintf("attr_timeout=%d", timeout))
		args = append(args, "--fuse-option", fmt.Sprintf("entry_timeout=%d", timeout))
	}

	if options.MaxReadAhead > 0 {
		args = append(args, "--fuse-option", fmt.Sprintf("max_readahead=%d", options.MaxReadAhead))
	}

	return exec.Command(exePath, args...)
}

func (l *LinuxMounter) gracefulUnmount(mountPoint string) error {
	// Try fusermount first (preferred for FUSE filesystems)
	cmd := exec.Command("fusermount", "-u", mountPoint)
	if err := cmd.Run(); err != nil {
		// Fall back to umount
		cmd = exec.Command("umount", mountPoint)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("umount failed: %w", err)
		}
	}

	// Wait a moment for unmount to complete
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (l *LinuxMounter) forceUnmount(mountPoint string) error {
	// Try force unmount with fusermount
	cmd := exec.Command("fusermount", "-u", "-z", mountPoint)
	if err := cmd.Run(); err != nil {
		// Fall back to lazy umount
		cmd = exec.Command("umount", "-l", mountPoint)
		if err := cmd.Run(); err != nil {
			// Last resort: force umount
			cmd = exec.Command("umount", "-f", mountPoint)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("force unmount failed: %w", err)
			}
		}
	}

	// Wait for unmount to complete
	time.Sleep(1 * time.Second)
	return nil
}

func (l *LinuxMounter) isProcessRunning(process *os.Process) bool {
	if process == nil {
		return false
	}

	// Check if process is still running by sending signal 0
	err := process.Signal(syscall.Signal(0))
	return err == nil
}

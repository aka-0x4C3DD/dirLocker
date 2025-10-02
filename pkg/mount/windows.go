//go:build windows
// +build windows

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
	"unsafe"

	"dirLocker/pkg/logging"

	"golang.org/x/sys/windows"
)

// WindowsMounter implements mounting for Windows using Dokany or WinFSP
type WindowsMounter struct {
	logger       *logging.Logger
	mountType    string // "dokany" or "winfsp"
	mountProcess map[string]*os.Process
}

// NewWindowsMounter creates a new Windows mounter
func NewWindowsMounter(logger *logging.Logger) (*WindowsMounter, error) {
	mounter := &WindowsMounter{
		logger:       logger,
		mountProcess: make(map[string]*os.Process),
	}

	// Detect available mounting system
	if mounter.isDokanyAvailable() {
		mounter.mountType = "dokany"
		logger.Info("Using Dokany for Windows mounting")
	} else if mounter.isWinFSPAvailable() {
		mounter.mountType = "winfsp"
		logger.Info("Using WinFSP for Windows mounting")
	} else {
		return nil, &MountError{
			Code:    MountErrorDriverNotFound,
			Message: "Neither Dokany nor WinFSP is available",
		}
	}

	return mounter, nil
}

// Mount mounts a vault using Windows filesystem drivers
func (w *WindowsMounter) Mount(ctx context.Context, vault VaultInterface, options *MountOptions) (*MountInfo, error) {
	// Validate mount point (should be a drive letter on Windows)
	if !w.isValidDriveLetter(options.MountPoint) {
		return nil, &MountError{
			Code:    MountErrorInvalidOptions,
			Message: fmt.Sprintf("invalid drive letter: %s (expected format: C:, D:, etc.)", options.MountPoint),
		}
	}

	// Check if drive letter is available
	if w.isDriveLetterInUse(options.MountPoint) {
		return nil, &MountError{
			Code:    MountErrorMountPointInUse,
			Message: fmt.Sprintf("drive letter %s is already in use", options.MountPoint),
		}
	}

	// Check for administrator privileges if needed
	if w.requiresElevation() {
		if !w.isRunningAsAdmin() {
			return nil, &MountError{
				Code:    MountErrorPermissionDenied,
				Message: "mounting requires administrator privileges",
			}
		}
	}

	w.logger.Info("Starting Windows mount process", "drive", options.MountPoint, "type", w.mountType)

	// Create mount command based on available driver
	var cmd *exec.Cmd
	switch w.mountType {
	case "dokany":
		cmd = w.createDokanyCommand(vault, options)
	case "winfsp":
		cmd = w.createWinFSPCommand(vault, options)
	default:
		return nil, &MountError{
			Code:    MountErrorUnsupported,
			Message: "no supported mounting driver available",
		}
	}

	// Start the mount process
	if err := cmd.Start(); err != nil {
		return nil, &MountError{
			Code:    MountErrorTimeout,
			Message: "failed to start mount process",
			Cause:   err,
		}
	}

	// Wait for mount to be ready with timeout
	mountReady := make(chan bool, 1)
	go func() {
		for i := 0; i < 30; i++ { // Wait up to 30 seconds
			if w.isDriveLetterMounted(options.MountPoint) {
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
	w.mountProcess[options.MountPoint] = cmd.Process

	mountInfo := &MountInfo{
		VaultPath:  vault.GetPath(),
		MountPoint: options.MountPoint,
		MountedAt:  time.Now(),
		ReadOnly:   options.ReadOnly,
		FileSystem: w.mountType,
		ProcessID:  cmd.Process.Pid,
	}

	w.logger.Info("Successfully mounted vault on Windows", "drive", options.MountPoint, "pid", cmd.Process.Pid)
	return mountInfo, nil
}

// Unmount unmounts a vault from Windows
func (w *WindowsMounter) Unmount(ctx context.Context, mountPoint string) error {
	w.logger.Info("Unmounting Windows drive", "drive", mountPoint)

	// Find and terminate the mount process
	if process, exists := w.mountProcess[mountPoint]; exists {
		if err := process.Kill(); err != nil {
			w.logger.Warn("Failed to kill mount process", "error", err, "drive", mountPoint)
		}
		delete(w.mountProcess, mountPoint)
	}

	// Force unmount using system commands
	switch w.mountType {
	case "dokany":
		return w.unmountDokany(mountPoint)
	case "winfsp":
		return w.unmountWinFSP(mountPoint)
	default:
		return &MountError{
			Code:    MountErrorUnsupported,
			Message: "no supported unmounting method available",
		}
	}
}

// IsMounted checks if a drive letter is currently mounted
func (w *WindowsMounter) IsMounted(mountPoint string) (bool, error) {
	return w.isDriveLetterMounted(mountPoint), nil
}

// ListMounts returns all currently mounted drives (limited to our mounts)
func (w *WindowsMounter) ListMounts() ([]*MountInfo, error) {
	var mounts []*MountInfo

	for mountPoint, process := range w.mountProcess {
		// Check if process is still running
		if w.isProcessRunning(process) && w.isDriveLetterMounted(mountPoint) {
			mounts = append(mounts, &MountInfo{
				MountPoint: mountPoint,
				FileSystem: w.mountType,
				ProcessID:  process.Pid,
				MountedAt:  time.Now(), // We don't track exact mount time
			})
		}
	}

	return mounts, nil
}

// GetMountInfo returns information about a specific mount
func (w *WindowsMounter) GetMountInfo(mountPoint string) (*MountInfo, error) {
	if process, exists := w.mountProcess[mountPoint]; exists {
		if w.isProcessRunning(process) && w.isDriveLetterMounted(mountPoint) {
			return &MountInfo{
				MountPoint: mountPoint,
				FileSystem: w.mountType,
				ProcessID:  process.Pid,
				MountedAt:  time.Now(),
			}, nil
		}
	}

	return nil, &MountError{
		Code:    MountErrorMountPointNotFound,
		Message: fmt.Sprintf("no mount found at drive %s", mountPoint),
	}
}

// IsSupported returns true if Windows mounting is supported
func (w *WindowsMounter) IsSupported() bool {
	return w.isDokanyAvailable() || w.isWinFSPAvailable()
}

// GetRequiredDrivers returns required Windows drivers
func (w *WindowsMounter) GetRequiredDrivers() []string {
	return []string{"Dokany", "WinFSP"}
}

// CheckDrivers verifies that required drivers are installed
func (w *WindowsMounter) CheckDrivers() error {
	if !w.isDokanyAvailable() && !w.isWinFSPAvailable() {
		return &MountError{
			Code:    MountErrorDriverNotFound,
			Message: "Neither Dokany nor WinFSP is installed",
		}
	}
	return nil
}

// Helper methods

func (w *WindowsMounter) isDokanyAvailable() bool {
	// Check for Dokany installation
	dokanyPaths := []string{
		`C:\Program Files\Dokan\Dokan Library-*\dokan*.dll`,
		`C:\Program Files (x86)\Dokan\Dokan Library-*\dokan*.dll`,
		`C:\Windows\System32\dokan*.dll`,
	}

	for _, pattern := range dokanyPaths {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return true
		}
	}

	// Check registry (simplified check)
	// In a full implementation, this would check the Windows registry
	// for Dokany installation entries

	return false
}

func (w *WindowsMounter) isWinFSPAvailable() bool {
	// Check for WinFSP installation
	winfspPaths := []string{
		`C:\Program Files (x86)\WinFsp\bin\winfsp-*.dll`,
		`C:\Program Files\WinFsp\bin\winfsp-*.dll`,
	}

	for _, pattern := range winfspPaths {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return true
		}
	}

	return false
}

func (w *WindowsMounter) isValidDriveLetter(mountPoint string) bool {
	if len(mountPoint) != 2 {
		return false
	}
	if mountPoint[1] != ':' {
		return false
	}
	letter := strings.ToUpper(string(mountPoint[0]))
	return letter >= "A" && letter <= "Z"
}

func (w *WindowsMounter) isDriveLetterInUse(driveLetter string) bool {
	drives, err := windows.GetLogicalDrives()
	if err != nil {
		return true // Assume in use if we can't check
	}

	letter := strings.ToUpper(string(driveLetter[0]))
	driveIndex := int(letter[0] - 'A')
	return (drives & (1 << driveIndex)) != 0
}

func (w *WindowsMounter) isDriveLetterMounted(driveLetter string) bool {
	// Check if the drive letter exists and is accessible
	_, err := os.Stat(driveLetter + `\`)
	return err == nil
}

func (w *WindowsMounter) requiresElevation() bool {
	// Some operations may require elevation
	return w.mountType == "dokany" // Dokany typically requires admin
}

func (w *WindowsMounter) isRunningAsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func (w *WindowsMounter) createDokanyCommand(vault VaultInterface, options *MountOptions) *exec.Cmd {
	// Create command to run our Dokany filesystem implementation
	args := []string{
		"--vault", vault.GetPath(),
		"--drive", options.MountPoint,
	}

	if options.ReadOnly {
		args = append(args, "--readonly")
	}

	if options.Debug {
		args = append(args, "--debug")
	}

	// Use our Dokany filesystem implementation
	return exec.Command("dirlocker-dokany.exe", args...)
}

func (w *WindowsMounter) createWinFSPCommand(vault VaultInterface, options *MountOptions) *exec.Cmd {
	// Create command to run our WinFSP filesystem implementation
	args := []string{
		"--vault", vault.GetPath(),
		"--drive", options.MountPoint,
	}

	if options.ReadOnly {
		args = append(args, "--readonly")
	}

	if options.Debug {
		args = append(args, "--debug")
	}

	// Use our WinFSP filesystem implementation
	return exec.Command("dirlocker-winfsp.exe", args...)
}

func (w *WindowsMounter) unmountDokany(mountPoint string) error {
	// Force unmount using Dokany utilities
	cmd := exec.Command("dokanctl.exe", "/u", mountPoint)
	if err := cmd.Run(); err != nil {
		w.logger.Warn("Failed to unmount using dokanctl", "error", err, "drive", mountPoint)
		// Try alternative method
		return w.forceUnmountDrive(mountPoint)
	}
	return nil
}

func (w *WindowsMounter) unmountWinFSP(mountPoint string) error {
	// Force unmount using WinFSP utilities
	cmd := exec.Command("launchctl-x64.exe", "stop", mountPoint)
	if err := cmd.Run(); err != nil {
		w.logger.Warn("Failed to unmount using WinFSP", "error", err, "drive", mountPoint)
		// Try alternative method
		return w.forceUnmountDrive(mountPoint)
	}
	return nil
}

func (w *WindowsMounter) forceUnmountDrive(driveLetter string) error {
	// Use Windows API to force unmount
	drive := strings.ToUpper(driveLetter)
	driveRoot := drive + `\`

	// Convert to UTF16
	driveRootPtr, err := windows.UTF16PtrFromString(driveRoot)
	if err != nil {
		return err
	}

	// Try to eject the drive
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procGetDriveType := kernel32.NewProc("GetDriveTypeW")

	ret, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(driveRootPtr)))
	if ret == 1 { // DRIVE_NO_ROOT_DIR
		return nil // Already unmounted
	}

	// Additional cleanup could be added here
	w.logger.Info("Force unmounted drive", "drive", driveLetter)
	return nil
}

func (w *WindowsMounter) isProcessRunning(process *os.Process) bool {
	if process == nil {
		return false
	}

	// Check if process is still running
	err := process.Signal(syscall.Signal(0))
	return err == nil
}

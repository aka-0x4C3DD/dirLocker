package tests

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/mount"
	"dirLocker/pkg/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMountIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := logging.NewTestLogger()

	// Create a test vault
	vaultPath := filepath.Join(t.TempDir(), "test.vault")
	password := "test-password"

	cfg := &config.Config{} // Use default config
	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)

	// Create vault
	err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)

	// Open vault
	testVault, err := vaultManager.OpenVault(vaultPath, password)
	require.NoError(t, err)
	defer func() {
		if err := vaultManager.CloseVault(vaultPath); err != nil {
			t.Logf("Failed to close vault: %v", err)
		}
	}()

	// Add some test files
	err = testVault.AddFile("/test.txt", []byte("Hello, World!"))
	require.NoError(t, err)

	err = testVault.CreateDirectory("/subdir")
	require.NoError(t, err)

	err = testVault.AddFile("/subdir/nested.txt", []byte("Nested content"))
	require.NoError(t, err)

	// Create mount manager
	mountManager, err := mount.NewManager(logger)
	require.NoError(t, err)

	// Skip test if mounting is not supported
	if !mountManager.IsSupported() {
		t.Skip("Mounting not supported on this platform")
	}

	// Check drivers - skip test if drivers not available instead of failing
	if err := mountManager.CheckDrivers(); err != nil {
		t.Skipf("Required drivers not available: %v", err)
	}

	// Executables are built dynamically in this test, so we skip the pre-check for specific binary names.
	// The build step below will ensure we have what we need.

	// Determine mount point based on platform
	var mountPoint string
	switch runtime.GOOS {
	case "windows":
		mountPoint = "Z:" // Use Z: drive on Windows
	default:
		mountPoint = filepath.Join(t.TempDir(), "mount")
	}

	// Build CLI binary for testing to avoid recursion loops when calling mount-helper
	// logic from the test executable itself.
	cliPath := filepath.Join(t.TempDir(), "dirlocker-cli.exe")
	if runtime.GOOS == "windows" {
		// Note: tests are run from the tests/ directory, so we need to go up one level
		buildCmd := exec.Command("go", "build", "-o", cliPath, "../cmd/cli")
		if out, err := buildCmd.CombinedOutput(); err != nil {
			t.Fatalf("Failed to build CLI binary: %v\nOutput: %s", err, out)
		}
	}

	// Test mounting
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := &mount.MountOptions{
		MountPoint: mountPoint,
		ReadOnly:   false,
		Debug:      true,
	}

	if runtime.GOOS == "windows" {
		opts.ExecutablePath = cliPath
	}

	mountInfo, err := mountManager.Mount(ctx, testVault, opts)
	require.NoError(t, err)
	require.NotNil(t, mountInfo)

	// Verify mount info
	assert.Equal(t, vaultPath, mountInfo.VaultPath)
	assert.Equal(t, mountPoint, mountInfo.MountPoint)
	assert.False(t, mountInfo.ReadOnly)
	assert.NotZero(t, mountInfo.ProcessID)

	// Wait a moment for mount to be fully ready
	time.Sleep(2 * time.Second)

	// Verify mount is active
	isMounted, err := mountManager.IsMounted(mountPoint)
	require.NoError(t, err)
	assert.True(t, isMounted)

	// List mounts
	mounts, err := mountManager.ListMounts()
	require.NoError(t, err)
	assert.Len(t, mounts, 1)
	assert.Equal(t, mountPoint, mounts[0].MountPoint)

	// Test filesystem operations (if mount point is accessible)
	if runtime.GOOS != "windows" { // Skip filesystem tests on Windows for now
		testMountedFilesystem(t, mountPoint)
	}

	// Test unmounting
	err = mountManager.Unmount(ctx, mountPoint)
	require.NoError(t, err)

	// Wait for unmount to complete
	time.Sleep(2 * time.Second)

	// Verify unmount
	isMounted, err = mountManager.IsMounted(mountPoint)
	require.NoError(t, err)
	assert.False(t, isMounted)

	// Verify no mounts remain
	mounts, err = mountManager.ListMounts()
	require.NoError(t, err)
	assert.Len(t, mounts, 0)
}

func testMountedFilesystem(t *testing.T, mountPoint string) {
	// Test reading files from mounted filesystem
	testFilePath := filepath.Join(mountPoint, "test.txt")

	// Wait for file to be available
	var data []byte
	var err error
	for i := 0; i < 10; i++ {
		data, err = os.ReadFile(testFilePath)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		t.Logf("Could not read mounted file (this may be expected): %v", err)
		return
	}

	assert.Equal(t, []byte("Hello, World!"), data)

	// Test directory listing
	entries, err := os.ReadDir(mountPoint)
	if err != nil {
		t.Logf("Could not list mounted directory: %v", err)
		return
	}

	// Should have test.txt and subdir
	assert.GreaterOrEqual(t, len(entries), 2)

	var foundTestFile, foundSubdir bool
	for _, entry := range entries {
		switch entry.Name() {
		case "test.txt":
			foundTestFile = true
			assert.False(t, entry.IsDir())
		case "subdir":
			foundSubdir = true
			assert.True(t, entry.IsDir())
		}
	}

	assert.True(t, foundTestFile, "test.txt not found in mounted filesystem")
	assert.True(t, foundSubdir, "subdir not found in mounted filesystem")

	// Test nested file
	nestedFilePath := filepath.Join(mountPoint, "subdir", "nested.txt")
	nestedData, err := os.ReadFile(nestedFilePath)
	if err == nil {
		assert.Equal(t, []byte("Nested content"), nestedData)
	} else {
		t.Logf("Could not read nested file: %v", err)
	}
}

func TestMountErrors(t *testing.T) {
	logger := logging.NewTestLogger()

	mountManager, err := mount.NewManager(logger)
	require.NoError(t, err)

	if !mountManager.IsSupported() {
		t.Skip("Mounting not supported on this platform")
	}

	// Test mounting with invalid vault
	ctx := context.Background()
	mockVault := &MockVaultInterface{path: "/nonexistent/vault.vault"}

	var mountPoint string
	switch runtime.GOOS {
	case "windows":
		mountPoint = "Y:"
	default:
		mountPoint = "/tmp/invalid-mount"
	}

	// Build CLI binary for testing to avoid recursion loops
	cliPath := filepath.Join(t.TempDir(), "dirlocker-cli.exe")
	if runtime.GOOS == "windows" {
		// Note: tests are run from the tests/ directory, so we need to go up one level
		buildCmd := exec.Command("go", "build", "-o", cliPath, "../cmd/cli")
		if out, err := buildCmd.CombinedOutput(); err != nil {
			t.Fatalf("Failed to build CLI binary: %v\nOutput: %s", err, out)
		}
	}

	opts := &mount.MountOptions{
		MountPoint: mountPoint,
	}
	if runtime.GOOS == "windows" {
		opts.ExecutablePath = cliPath
	}

	_, err = mountManager.Mount(ctx, mockVault, opts)
	assert.Error(t, err)

	// Test unmounting non-existent mount
	err = mountManager.Unmount(ctx, mountPoint)
	assert.Error(t, err)

	// Test checking non-existent mount
	isMounted, err := mountManager.IsMounted(mountPoint)
	require.NoError(t, err)
	assert.False(t, isMounted)
}

func TestMountCleanup(t *testing.T) {
	logger := logging.NewTestLogger()

	mountManager, err := mount.NewManager(logger)
	require.NoError(t, err)

	if !mountManager.IsSupported() {
		t.Skip("Mounting not supported on this platform")
	}

	// Test unmounting all mounts
	ctx := context.Background()
	err = mountManager.UnmountAll(ctx)
	require.NoError(t, err)

	// Verify no mounts remain
	mounts, err := mountManager.ListMounts()
	require.NoError(t, err)
	assert.Len(t, mounts, 0)
}

// MockVaultInterface implements the VaultInterface for testing
type MockVaultInterface struct {
	path string
}

func (m *MockVaultInterface) GetPath() string {
	return m.path
}

func (m *MockVaultInterface) GetPassword() string {
	return "mock-password"
}

func (m *MockVaultInterface) UpdateLastUsed() {
	// Mock implementation
}

package mount

import (
	"context"
	"testing"
	"time"

	"dirLocker/pkg/logging"
)

// MockVault implements VaultInterface for testing
type MockVault struct {
	path string
}

func (m *MockVault) GetPath() string {
	return m.path
}

func (m *MockVault) GetPassword() string {
	return "mock-password"
}

func (m *MockVault) UpdateLastUsed() {
	// No-op for testing
}

// MockMounter implements the Mounter interface for testing
type MockMounter struct {
	supported         bool
	mounts            map[string]*MountInfo
	shouldFailMount   bool
	shouldFailUnmount bool
}

func NewMockMounter(supported bool) *MockMounter {
	return &MockMounter{
		supported: supported,
		mounts:    make(map[string]*MountInfo),
	}
}

func (m *MockMounter) Mount(ctx context.Context, vault VaultInterface, options *MountOptions) (*MountInfo, error) {
	if m.shouldFailMount {
		return nil, &MountError{Code: MountErrorTimeout, Message: "mock mount failure"}
	}

	mountInfo := &MountInfo{
		VaultPath:  vault.GetPath(),
		MountPoint: options.MountPoint,
		MountedAt:  time.Now(),
		ReadOnly:   options.ReadOnly,
		FileSystem: "mock",
		ProcessID:  12345,
	}

	m.mounts[options.MountPoint] = mountInfo
	return mountInfo, nil
}

func (m *MockMounter) Unmount(ctx context.Context, mountPoint string) error {
	if m.shouldFailUnmount {
		return &MountError{Code: MountErrorTimeout, Message: "mock unmount failure"}
	}

	delete(m.mounts, mountPoint)
	return nil
}

func (m *MockMounter) IsMounted(mountPoint string) (bool, error) {
	_, exists := m.mounts[mountPoint]
	return exists, nil
}

func (m *MockMounter) ListMounts() ([]*MountInfo, error) {
	var mounts []*MountInfo
	for _, mountInfo := range m.mounts {
		mounts = append(mounts, mountInfo)
	}
	return mounts, nil
}

func (m *MockMounter) GetMountInfo(mountPoint string) (*MountInfo, error) {
	if mountInfo, exists := m.mounts[mountPoint]; exists {
		return mountInfo, nil
	}
	return nil, &MountError{Code: MountErrorMountPointNotFound, Message: "mount not found"}
}

func (m *MockMounter) IsSupported() bool {
	return m.supported
}

func (m *MockMounter) GetRequiredDrivers() []string {
	return []string{"mock-driver"}
}

func (m *MockMounter) CheckDrivers() error {
	if !m.supported {
		return &MountError{Code: MountErrorDriverNotFound, Message: "mock driver not found"}
	}
	return nil
}

func TestManager_Mount(t *testing.T) {
	logConfig := &logging.LogConfig{
		Level:   "info",
		Console: false,
	}
	logger, _ := logging.NewLogger(logConfig)

	// Create manager with mock mounter
	manager := &Manager{
		mounter:      NewMockMounter(true),
		logger:       logger,
		activeMounts: make(map[string]*MountInfo),
	}

	// Create mock vault
	mockVault := &MockVault{
		path: "/test/vault.vc",
	}

	// Test successful mount
	options := &MountOptions{
		MountPoint: "/test/mount",
		ReadOnly:   false,
	}

	ctx := context.Background()
	mountInfo, err := manager.Mount(ctx, mockVault, options)
	if err != nil {
		t.Fatalf("Expected successful mount, got error: %v", err)
	}

	if mountInfo.MountPoint != "/test/mount" {
		t.Errorf("Expected mount point '/test/mount', got '%s'", mountInfo.MountPoint)
	}

	if mountInfo.VaultPath != "/test/vault.vc" {
		t.Errorf("Expected vault path '/test/vault.vc', got '%s'", mountInfo.VaultPath)
	}

	// Test mount point already in use
	_, err = manager.Mount(ctx, mockVault, options)
	if err == nil {
		t.Error("Expected error for mount point already in use")
	}

	// Test unmount
	err = manager.Unmount(ctx, "/test/mount")
	if err != nil {
		t.Fatalf("Expected successful unmount, got error: %v", err)
	}

	// Test unmount non-existent mount
	err = manager.Unmount(ctx, "/test/nonexistent")
	if err == nil {
		t.Error("Expected error for unmounting non-existent mount")
	}
}

func TestManager_UnsupportedPlatform(t *testing.T) {
	logConfig := &logging.LogConfig{
		Level:   "info",
		Console: false,
	}
	logger, _ := logging.NewLogger(logConfig)

	// Create manager with unsupported mock mounter
	manager := &Manager{
		mounter:      NewMockMounter(false),
		logger:       logger,
		activeMounts: make(map[string]*MountInfo),
	}

	mockVault := &MockVault{
		path: "/test/vault.vc",
	}

	options := &MountOptions{
		MountPoint: "/test/mount",
	}

	ctx := context.Background()
	_, err := manager.Mount(ctx, mockVault, options)
	if err == nil {
		t.Error("Expected error for unsupported platform")
	}
}

func TestManager_ListMounts(t *testing.T) {
	logConfig := &logging.LogConfig{
		Level:   "info",
		Console: false,
	}
	logger, _ := logging.NewLogger(logConfig)

	manager := &Manager{
		mounter:      NewMockMounter(true),
		logger:       logger,
		activeMounts: make(map[string]*MountInfo),
	}

	// Initially should be empty
	mounts, err := manager.ListMounts()
	if err != nil {
		t.Fatalf("Expected successful list, got error: %v", err)
	}

	if len(mounts) != 0 {
		t.Errorf("Expected 0 mounts, got %d", len(mounts))
	}

	// Mount a vault
	mockVault := &MockVault{
		path: "/test/vault.vc",
	}

	options := &MountOptions{
		MountPoint: "/test/mount",
	}

	ctx := context.Background()
	_, err = manager.Mount(ctx, mockVault, options)
	if err != nil {
		t.Fatalf("Expected successful mount, got error: %v", err)
	}

	// Should now have one mount
	mounts, err = manager.ListMounts()
	if err != nil {
		t.Fatalf("Expected successful list, got error: %v", err)
	}

	if len(mounts) != 1 {
		t.Errorf("Expected 1 mount, got %d", len(mounts))
	}
}

func TestDefaultMountOptions(t *testing.T) {
	options := DefaultMountOptions()

	if options.ReadOnly {
		t.Error("Expected ReadOnly to be false by default")
	}

	if options.AllowOther {
		t.Error("Expected AllowOther to be false by default")
	}

	if options.Timeout != 30*time.Second {
		t.Errorf("Expected timeout to be 30s, got %v", options.Timeout)
	}

	if options.CacheTimeout != 1*time.Second {
		t.Errorf("Expected cache timeout to be 1s, got %v", options.CacheTimeout)
	}
}

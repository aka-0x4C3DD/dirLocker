package filehider

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedRegistry_SaveAndLoad(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "filehider_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	registryPath := filepath.Join(tempDir, "test_registry.enc")
	password := "test-password"

	registry := NewEncryptedRegistry(registryPath, password)

	// Create test registry data
	testRegistry := &HiddenFileRegistry{
		Version: registryVersion,
		Files: map[string]HiddenFileInfo{
			"test.txt": {
				OriginalPath: "/path/to/test.txt",
				HiddenPath:   "/hidden/path/test.txt",
				HiddenAt:     time.Now(),
				FileSize:     1024,
				Permissions:  0644,
				Checksum:     "abcd1234",
			},
		},
		Salt: make([]byte, saltSize),
	}

	// Save registry
	err = registry.Save(testRegistry)
	if err != nil {
		t.Fatalf("Failed to save registry: %v", err)
	}

	// Load registry
	loadedRegistry, err := registry.Load()
	if err != nil {
		t.Fatalf("Failed to load registry: %v", err)
	}

	// Verify data
	if loadedRegistry.Version != testRegistry.Version {
		t.Errorf("Version mismatch: expected %d, got %d", testRegistry.Version, loadedRegistry.Version)
	}

	if len(loadedRegistry.Files) != len(testRegistry.Files) {
		t.Errorf("Files count mismatch: expected %d, got %d", len(testRegistry.Files), len(loadedRegistry.Files))
	}

	testFile, exists := loadedRegistry.Files["test.txt"]
	if !exists {
		t.Error("Test file not found in loaded registry")
	}

	if testFile.OriginalPath != testRegistry.Files["test.txt"].OriginalPath {
		t.Errorf("OriginalPath mismatch: expected %s, got %s",
			testRegistry.Files["test.txt"].OriginalPath, testFile.OriginalPath)
	}
}

func TestEncryptedRegistry_LoadNonExistent(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "filehider_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	registryPath := filepath.Join(tempDir, "nonexistent_registry.enc")
	password := "test-password"

	registry := NewEncryptedRegistry(registryPath, password)

	// Load non-existent registry should return empty registry
	loadedRegistry, err := registry.Load()
	if err != nil {
		t.Fatalf("Failed to load non-existent registry: %v", err)
	}

	if loadedRegistry.Version != registryVersion {
		t.Errorf("Version mismatch: expected %d, got %d", registryVersion, loadedRegistry.Version)
	}

	if len(loadedRegistry.Files) != 0 {
		t.Errorf("Expected empty files map, got %d files", len(loadedRegistry.Files))
	}
}

func TestEncryptedRegistry_WrongPassword(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "filehider_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	registryPath := filepath.Join(tempDir, "test_registry.enc")
	correctPassword := "correct-password"
	wrongPassword := "wrong-password"

	// Save with correct password
	registry := NewEncryptedRegistry(registryPath, correctPassword)
	testRegistry := &HiddenFileRegistry{
		Version: registryVersion,
		Files:   make(map[string]HiddenFileInfo),
		Salt:    make([]byte, saltSize),
	}

	err = registry.Save(testRegistry)
	if err != nil {
		t.Fatalf("Failed to save registry: %v", err)
	}

	// Try to load with wrong password
	wrongRegistry := NewEncryptedRegistry(registryPath, wrongPassword)
	_, err = wrongRegistry.Load()
	if err == nil {
		t.Error("Expected error when loading with wrong password, but got none")
	}
}

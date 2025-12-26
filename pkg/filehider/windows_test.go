//go:build windows

package filehider

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWindowsFileHider_HideAndUnhideFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "filehider_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test file
	testFile := filepath.Join(tempDir, "test_file.txt")
	testContent := "This is a test file for hiding"
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create file hider with a specific test root to ensure isolation
	testHiderRoot := filepath.Join(tempDir, "hider_root")
	hider, err := newWindowsFileHiderWithRoot(testHiderRoot)
	if err != nil {
		t.Fatalf("Failed to create Windows file hider: %v", err)
	}

	// Test hiding the file
	err = hider.HideFile(testFile)
	if err != nil {
		t.Fatalf("Failed to hide file: %v", err)
	}

	// Verify file is no longer at original location
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("File should not exist at original location after hiding")
	}

	// Verify file is marked as hidden
	if !hider.IsHidden(testFile) {
		t.Error("File should be marked as hidden")
	}

	// List hidden files
	hiddenFiles, err := hider.ListHidden()
	if err != nil {
		t.Fatalf("Failed to list hidden files: %v", err)
	}

	if len(hiddenFiles) != 1 {
		t.Errorf("Expected 1 hidden file, got %d", len(hiddenFiles))
	}

	// Test unhiding the file
	fileName := filepath.Base(testFile)
	err = hider.UnhideFile(fileName)
	if err != nil {
		t.Fatalf("Failed to unhide file: %v", err)
	}

	// Verify file is back at original location
	if _, err := os.Stat(testFile); err != nil {
		t.Errorf("File should exist at original location after unhiding: %v", err)
	}

	// Verify content is intact
	restoredContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read restored file: %v", err)
	}

	if string(restoredContent) != testContent {
		t.Errorf("File content mismatch: expected %s, got %s", testContent, string(restoredContent))
	}

	// Verify file is no longer marked as hidden
	if hider.IsHidden(testFile) {
		t.Error("File should not be marked as hidden after unhiding")
	}
}

func TestWindowsFileHider_HideDirectory(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "filehider_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test directory with files
	testDir := filepath.Join(tempDir, "test_directory")
	err = os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create files in the directory
	testFile1 := filepath.Join(testDir, "file1.txt")
	testFile2 := filepath.Join(testDir, "file2.txt")
	err = os.WriteFile(testFile1, []byte("Content 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file 1: %v", err)
	}
	err = os.WriteFile(testFile2, []byte("Content 2"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file 2: %v", err)
	}

	// Create file hider with a specific test root to ensure isolation
	testHiderRoot := filepath.Join(tempDir, "hider_root")
	hider, err := newWindowsFileHiderWithRoot(testHiderRoot)
	if err != nil {
		t.Fatalf("Failed to create Windows file hider: %v", err)
	}

	// Test hiding the directory
	err = hider.HideFile(testDir)
	if err != nil {
		t.Fatalf("Failed to hide directory: %v", err)
	}

	// Verify directory is no longer at original location
	if _, err := os.Stat(testDir); !os.IsNotExist(err) {
		t.Error("Directory should not exist at original location after hiding")
	}

	// Test unhiding the directory
	dirName := filepath.Base(testDir)
	err = hider.UnhideFile(dirName)
	if err != nil {
		t.Fatalf("Failed to unhide directory: %v", err)
	}

	// Verify directory is back at original location
	if _, err := os.Stat(testDir); err != nil {
		t.Errorf("Directory should exist at original location after unhiding: %v", err)
	}

	// Verify files are intact
	content1, err := os.ReadFile(testFile1)
	if err != nil {
		t.Errorf("Failed to read restored file 1: %v", err)
	} else if string(content1) != "Content 1" {
		t.Errorf("File 1 content mismatch: expected 'Content 1', got %s", string(content1))
	}

	content2, err := os.ReadFile(testFile2)
	if err != nil {
		t.Errorf("Failed to read restored file 2: %v", err)
	} else if string(content2) != "Content 2" {
		t.Errorf("File 2 content mismatch: expected 'Content 2', got %s", string(content2))
	}
}

func TestWindowsFileHider_HideNonExistentFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	// Create temporary directory for test root
	tempDir, err := os.MkdirTemp("", "filehider_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testHiderRoot := filepath.Join(tempDir, "hider_root")
	hider, err := newWindowsFileHiderWithRoot(testHiderRoot)
	if err != nil {
		t.Fatalf("Failed to create Windows file hider: %v", err)
	}

	// Try to hide non-existent file
	err = hider.HideFile("non_existent_file.txt")
	if err == nil {
		t.Error("Expected error when hiding non-existent file, but got none")
	}
}

func TestWindowsFileHider_UnhideNonExistentFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	// Create temporary directory for test root
	tempDir, err := os.MkdirTemp("", "filehider_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testHiderRoot := filepath.Join(tempDir, "hider_root")
	hider, err := newWindowsFileHiderWithRoot(testHiderRoot)
	if err != nil {
		t.Fatalf("Failed to create Windows file hider: %v", err)
	}

	// Try to unhide non-existent file
	err = hider.UnhideFile("non_existent_file.txt")
	if err == nil {
		t.Error("Expected error when unhiding non-existent file, but got none")
	}
}

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultLifecycle(t *testing.T) {
	// 1. Setup
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test.vault")
	password := "securepassword123"

	// 2. Create Vault
	// CreateVault signature: func CreateVault(path, password string, cipher CipherType) (*VaultHandle, error)
	handle, err := CreateVault(vaultPath, password, CipherAES256GCM)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	handle.Close()

	// 3. Open Vault (Success)
	material := &UnlockMaterial{
		Password: password,
	}
	manager, err := OpenVault(vaultPath, material)
	if err != nil {
		t.Fatalf("Failed to open vault with correct password: %v", err)
	}
	defer manager.Close()

	// 4. Verify basic properties (if any exposed)
	// For example, listing files should be empty
	files, err := manager.ListFiles()
	if err != nil {
		t.Fatalf("Failed to list files: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("Expected 0 files, got %d", len(files))
	}

	// 5. Add File
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := []byte("Hello Vault!")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	err = manager.AddFile("/docs/test.txt", testContent)
	if err != nil {
		t.Fatalf("Failed to add file: %v", err)
	}

	// 6. List and Verify
	files, err = manager.ListFiles()
	if err != nil {
		t.Fatalf("Failed to list files after add: %v", err)
	}
	found := false
	for _, f := range files {
		if f.Name == "/docs/test.txt" {
			found = true
			if f.Size != uint64(len(testContent)) {
				t.Errorf("Expected size %d, got %d", len(testContent), f.Size)
			}
			break
		}
	}
	if !found {
		t.Errorf("File /docs/test.txt not found in listing")
	}

	// 7. Extract File
	extractPath := filepath.Join(tempDir, "extracted.txt")
	extractedBytes, err := manager.ExtractFile("/docs/test.txt")
	if err != nil {
		t.Fatalf("Failed to extract file: %v", err)
	}
	if err := os.WriteFile(extractPath, extractedBytes, 0644); err != nil {
		t.Fatalf("Failed to write extracted file: %v", err)
	}

	extractedContent, err := os.ReadFile(extractPath)
	if err != nil {
		t.Fatalf("Failed to read extracted file: %v", err)
	}
	if string(extractedContent) != string(testContent) {
		t.Errorf("Content mismatch. Expected %q, got %q", testContent, extractedContent)
	}
}

func TestVaultAccessDenied(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "denied.vault")
	password := "correct"

	handle, err := CreateVault(vaultPath, password, CipherAES256GCM)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	handle.Close()

	// Try wrong password
	material := &UnlockMaterial{
		Password: "wrong",
	}
	_, err = OpenVault(vaultPath, material)
	if err == nil {
		t.Error("Expected error opening vault with wrong password, got nil")
	}
}

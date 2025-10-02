package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"dirLocker/pkg/config"
	"dirLocker/pkg/vault"
)

// TestSimpleDirectoryCreation tests basic directory creation to understand the issue
func TestSimpleDirectoryCreation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "simple_directory_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DefaultCipher:   "xchacha20-poly1305",
		AutoLockTimeout: 0,
		LogLevel:        "debug",
	}

	logger, err := createTestLogger()
	require.NoError(t, err)

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	vaultPath := filepath.Join(tempDir, "test.vault")
	password := "test-password"

	err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)

	managedVault, err := vaultManager.OpenVault(vaultPath, password)
	require.NoError(t, err)

	// Test 1: Simple directory name (should work)
	t.Log("Testing simple directory name...")
	err = managedVault.CreateDirectory("documents")
	require.NoError(t, err, "Simple directory should work")

	// Test 2: Directory with slash (might not work)
	t.Log("Testing directory with slash...")
	err = managedVault.CreateDirectory("work/projects")
	if err != nil {
		t.Logf("Directory with slash failed as expected: %v", err)
	} else {
		t.Log("Directory with slash worked!")
	}

	// Test 3: Create parent first, then child
	t.Log("Testing parent then child...")
	err = managedVault.CreateDirectory("parent")
	require.NoError(t, err, "Parent directory should work")

	err = managedVault.CreateDirectory("parent/child")
	if err != nil {
		t.Logf("Child directory with slash failed: %v", err)
	} else {
		t.Log("Child directory with slash worked!")
	}

	// Test 4: Try different path separators
	t.Log("Testing different separators...")
	err = managedVault.CreateDirectory("test\\windows")
	if err != nil {
		t.Logf("Windows-style path failed: %v", err)
	} else {
		t.Log("Windows-style path worked!")
	}

	// List all files to see what was created
	files, err := managedVault.ListFiles()
	require.NoError(t, err)

	t.Log("Created files/directories:")
	for _, file := range files {
		t.Logf("  %s (dir: %v)", file.Name, file.IsDir)
	}
}

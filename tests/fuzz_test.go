package tests

import (
	"os"
	"path/filepath"
	"testing"

	"dirLocker/pkg/vault"
)

// FuzzVaultOpen tests the VaultOpen function with random data to ensure it doesn't crash.
func FuzzVaultOpen(f *testing.F) {
	// Seed with a basic "VLT1" header to pass the initial check potentially
	f.Add([]byte("VLT1\x02\x00\x00\x00\x00"))
	f.Add([]byte("random garbage data"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Write the fuzz data to a temporary file
		tempDir := t.TempDir()
		vaultPath := filepath.Join(tempDir, "fuzz.vault")
		if err := os.WriteFile(vaultPath, data, 0644); err != nil {
			t.Skip("Failed to write fuzz data file")
		}

		// Attempt to open the vault with a dummy password
		// We use a stub UnlockMaterial
		material := &vault.UnlockMaterial{
			Password: "password123",
		}

		// Call the function under test
		// We expect this to fail for almost all inputs, but it MUST NOT panic or crash CGO
		handle, err := vault.OpenVault(vaultPath, material)
		
		if err == nil {
			// If it successfully opened (unlikely but possible if fuzzer generates valid vault),
			// we must close it to avoid leaks.
			handle.Close()
		}
	})
}

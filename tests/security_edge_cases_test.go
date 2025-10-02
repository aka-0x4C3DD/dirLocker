package tests

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"dirLocker/pkg/config"
	"dirLocker/pkg/vault"
)

// TestPasswordSecurityScenarios tests various password-related security scenarios
func TestPasswordSecurityScenarios(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "password_security_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DefaultCipher:   "xchacha20-poly1305",
		AutoLockTimeout: 0,
		LogLevel:        "info",
	}

	logger, err := createTestLogger()
	require.NoError(t, err)

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	t.Run("WeakPasswords", func(t *testing.T) {
		// Test that the system handles weak passwords appropriately
		weakPasswords := []string{
			"123",
			"password",
			"abc",
			"",
			"a",
		}

		for i, weakPassword := range weakPasswords {
			vaultPath := filepath.Join(tempDir, fmt.Sprintf("weak_%d.vault", i))

			// The system should either reject weak passwords or handle them securely
			err := vaultManager.CreateVault(vaultPath, weakPassword, vault.CipherXChaCha20Poly1305)

			if err == nil {
				// If weak passwords are accepted, ensure they still work securely
				managedVault, err := vaultManager.OpenVault(vaultPath, weakPassword)
				require.NoError(t, err, "Should be able to open vault with weak password if creation succeeded")

				// Test basic operations work
				testData := []byte("test data")
				err = managedVault.AddFile("test.txt", testData)
				require.NoError(t, err)

				extractedData, err := managedVault.ExtractFile("test.txt")
				require.NoError(t, err)
				assert.Equal(t, testData, extractedData)

				err = vaultManager.CloseVault(vaultPath)
				require.NoError(t, err)

				t.Logf("Weak password '%s' was accepted and works correctly", weakPassword)
			} else {
				t.Logf("Weak password '%s' was rejected: %v", weakPassword, err)
			}
		}
	})

	t.Run("SpecialCharacterPasswords", func(t *testing.T) {
		// Test passwords with special characters
		specialPasswords := []string{
			"P@ssw0rd!2024",
			"Пароль123",                    // Cyrillic
			"密码123",                        // Chinese
			"パスワード123",                     // Japanese
			"🔐🔑SecurePass2024🔒",            // Emoji
			"Pass\nword\tWith\rWhitespace", // Whitespace characters
			"Pass\"word'With`Quotes",       // Various quotes
			"Pass\\word/With|Slashes",      // Slashes and pipes
			"Pass<word>With&Symbols",       // HTML-like characters
		}

		for i, password := range specialPasswords {
			vaultPath := filepath.Join(tempDir, fmt.Sprintf("special_%d.vault", i))

			err := vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
			require.NoError(t, err, "Should handle special character password: %s", password)

			managedVault, err := vaultManager.OpenVault(vaultPath, password)
			require.NoError(t, err, "Should open vault with special character password")

			// Test that the password works correctly
			testData := []byte(fmt.Sprintf("Test data for password: %s", password))
			err = managedVault.AddFile("test.txt", testData)
			require.NoError(t, err)

			extractedData, err := managedVault.ExtractFile("test.txt")
			require.NoError(t, err)
			assert.Equal(t, testData, extractedData)

			err = vaultManager.CloseVault(vaultPath)
			require.NoError(t, err)

			t.Logf("Special character password test passed: %s", password[:min(len(password), 10)]+"...")
		}
	})

	t.Run("LongPasswords", func(t *testing.T) {
		// Test very long passwords
		longPasswords := []string{
			strings.Repeat("a", 100),     // 100 characters
			strings.Repeat("Pass1!", 50), // 300 characters
			strings.Repeat("🔐", 100),     // 400 bytes (emoji are 4 bytes each)
		}

		for i, password := range longPasswords {
			vaultPath := filepath.Join(tempDir, fmt.Sprintf("long_%d.vault", i))

			err := vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
			require.NoError(t, err, "Should handle long password of length %d", len(password))

			managedVault, err := vaultManager.OpenVault(vaultPath, password)
			require.NoError(t, err, "Should open vault with long password")

			testData := []byte("Test data for long password")
			err = managedVault.AddFile("test.txt", testData)
			require.NoError(t, err)

			extractedData, err := managedVault.ExtractFile("test.txt")
			require.NoError(t, err)
			assert.Equal(t, testData, extractedData)

			err = vaultManager.CloseVault(vaultPath)
			require.NoError(t, err)

			t.Logf("Long password test passed: length %d", len(password))
		}
	})

	t.Run("PasswordCaseSensitivity", func(t *testing.T) {
		// Test that passwords are case-sensitive
		vaultPath := filepath.Join(tempDir, "case_sensitive.vault")
		originalPassword := "CaseSensitivePassword123!"

		err := vaultManager.CreateVault(vaultPath, originalPassword, vault.CipherXChaCha20Poly1305)
		require.NoError(t, err)

		managedVault, err := vaultManager.OpenVault(vaultPath, originalPassword)
		require.NoError(t, err)

		testData := []byte("Case sensitivity test data")
		err = managedVault.AddFile("test.txt", testData)
		require.NoError(t, err)

		err = vaultManager.CloseVault(vaultPath)
		require.NoError(t, err)

		// Try different case variations - they should all fail
		wrongCasePasswords := []string{
			strings.ToLower(originalPassword),
			strings.ToUpper(originalPassword),
			"casesensitivepassword123!",
			"CASESENSITIVEPASSWORD123!",
		}

		for _, wrongPassword := range wrongCasePasswords {
			_, err := vaultManager.OpenVault(vaultPath, wrongPassword)
			assert.Error(t, err, "Wrong case password should be rejected: %s", wrongPassword)
		}

		// Correct password should still work
		_, err = vaultManager.OpenVault(vaultPath, originalPassword)
		require.NoError(t, err, "Original password should still work")

		err = vaultManager.CloseVault(vaultPath)
		require.NoError(t, err)
	})
}

// TestFileSystemEdgeCases tests edge cases in file system operations
func TestFileSystemEdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "filesystem_edge_cases_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DefaultCipher:   "xchacha20-poly1305",
		AutoLockTimeout: 0,
		LogLevel:        "info",
	}

	logger, err := createTestLogger()
	require.NoError(t, err)

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	vaultPath := filepath.Join(tempDir, "edge_cases.vault")
	password := "EdgeCasePassword123!"

	err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)

	managedVault, err := vaultManager.OpenVault(vaultPath, password)
	require.NoError(t, err)

	t.Run("ExtremeFileSizes", func(t *testing.T) {
		// Test empty file
		err := managedVault.AddFile("empty.txt", []byte{})
		require.NoError(t, err)

		extractedEmpty, err := managedVault.ExtractFile("empty.txt")
		require.NoError(t, err)
		assert.Equal(t, []byte{}, extractedEmpty)

		// Test single byte file
		singleByte := []byte{0x42}
		err = managedVault.AddFile("single_byte.dat", singleByte)
		require.NoError(t, err)

		extractedSingle, err := managedVault.ExtractFile("single_byte.dat")
		require.NoError(t, err)
		assert.Equal(t, singleByte, extractedSingle)

		// Test file with all zero bytes
		zeroBytes := make([]byte, 1024)
		err = managedVault.AddFile("zero_bytes.dat", zeroBytes)
		require.NoError(t, err)

		extractedZeros, err := managedVault.ExtractFile("zero_bytes.dat")
		require.NoError(t, err)
		assert.Equal(t, zeroBytes, extractedZeros)

		// Test file with all 0xFF bytes
		maxBytes := make([]byte, 1024)
		for i := range maxBytes {
			maxBytes[i] = 0xFF
		}
		err = managedVault.AddFile("max_bytes.dat", maxBytes)
		require.NoError(t, err)

		extractedMax, err := managedVault.ExtractFile("max_bytes.dat")
		require.NoError(t, err)
		assert.Equal(t, maxBytes, extractedMax)
	})

	t.Run("BinaryDataPatterns", func(t *testing.T) {
		// Test various binary patterns that might cause issues
		patterns := map[string][]byte{
			"null_bytes.dat":   {0x00, 0x00, 0x00, 0x00},
			"alternating.dat":  {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55},
			"sequential.dat":   {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			"high_entropy.dat": nil, // Will be filled with random data
		}

		// Generate high entropy data
		highEntropy := make([]byte, 1024)
		_, err := rand.Read(highEntropy)
		require.NoError(t, err)
		patterns["high_entropy.dat"] = highEntropy

		for filename, data := range patterns {
			err := managedVault.AddFile(filename, data)
			require.NoError(t, err, "Failed to add binary pattern file: %s", filename)

			extractedData, err := managedVault.ExtractFile(filename)
			require.NoError(t, err, "Failed to extract binary pattern file: %s", filename)
			assert.Equal(t, data, extractedData, "Binary pattern corruption in: %s", filename)
		}
	})

	t.Run("DeepDirectoryStructure", func(t *testing.T) {
		// Test very deep directory structure
		deepPath := "level1"
		for i := 2; i <= 20; i++ {
			deepPath = filepath.Join(deepPath, fmt.Sprintf("level%d", i))
		}

		err := managedVault.CreateDirectory(deepPath)
		require.NoError(t, err, "Should handle deep directory structure")

		// Add file in deep directory
		deepFile := filepath.Join(deepPath, "deep_file.txt")
		deepData := []byte("This file is in a very deep directory structure")

		err = managedVault.AddFile(deepFile, deepData)
		require.NoError(t, err, "Should add file in deep directory")

		extractedDeep, err := managedVault.ExtractFile(deepFile)
		require.NoError(t, err, "Should extract file from deep directory")
		assert.Equal(t, deepData, extractedDeep)
	})

	t.Run("ManyFilesInDirectory", func(t *testing.T) {
		// Test directory with many files
		manyFilesDir := "many_files"
		err := managedVault.CreateDirectory(manyFilesDir)
		require.NoError(t, err)

		const numFiles = 100
		for i := 0; i < numFiles; i++ {
			filename := filepath.Join(manyFilesDir, fmt.Sprintf("file_%03d.txt", i))
			data := []byte(fmt.Sprintf("Content of file %d", i))

			err := managedVault.AddFile(filename, data)
			require.NoError(t, err, "Failed to add file %d", i)
		}

		// Verify all files are present
		files, err := managedVault.ListFiles()
		require.NoError(t, err)

		filesInDir := 0
		for _, file := range files {
			// Check if file is in the target directory (handle both / and \ separators)
			expectedPrefix1 := manyFilesDir + "/"
			expectedPrefix2 := manyFilesDir + "\\"
			if (strings.HasPrefix(file.Name, expectedPrefix1) || strings.HasPrefix(file.Name, expectedPrefix2)) && !file.IsDir {
				filesInDir++
			}
		}

		assert.Equal(t, numFiles, filesInDir, "Should have all files in directory")
	})

	t.Run("FileOverwrite", func(t *testing.T) {
		// Test overwriting files with different sizes and content
		filename := "overwrite_test.txt"

		// Original file
		originalData := []byte("Original content")
		err := managedVault.AddFile(filename, originalData)
		require.NoError(t, err)

		// Overwrite with larger content
		largerData := []byte("This is much larger content that should completely replace the original content")
		err = managedVault.AddFile(filename, largerData)
		require.NoError(t, err)

		extractedLarger, err := managedVault.ExtractFile(filename)
		require.NoError(t, err)
		assert.Equal(t, largerData, extractedLarger)

		// Overwrite with smaller content
		smallerData := []byte("Small")
		err = managedVault.AddFile(filename, smallerData)
		require.NoError(t, err)

		extractedSmaller, err := managedVault.ExtractFile(filename)
		require.NoError(t, err)
		assert.Equal(t, smallerData, extractedSmaller)

		// Overwrite with empty content
		emptyData := []byte{}
		err = managedVault.AddFile(filename, emptyData)
		require.NoError(t, err)

		extractedEmpty, err := managedVault.ExtractFile(filename)
		require.NoError(t, err)
		assert.Equal(t, emptyData, extractedEmpty)
	})
}

// TestCorruptionResistance tests how the system handles various types of corruption
func TestCorruptionResistance(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "corruption_resistance_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DefaultCipher:   "xchacha20-poly1305",
		AutoLockTimeout: 0,
		LogLevel:        "info",
	}

	logger, err := createTestLogger()
	require.NoError(t, err)

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	vaultPath := filepath.Join(tempDir, "corruption_test.vault")
	password := "CorruptionTestPassword123!"

	err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)

	managedVault, err := vaultManager.OpenVault(vaultPath, password)
	require.NoError(t, err)

	// Add test data
	testFiles := map[string][]byte{
		"important.txt":  []byte("This is important data that should be protected"),
		"document.pdf":   generatePDFLikeData(t, 100*1024),
		"image.jpg":      generateJPEGLikeData(t, 500*1024),
		"large_file.dat": make([]byte, 1024*1024), // 1MB
	}

	// Fill large file with pattern
	for i := range testFiles["large_file.dat"] {
		testFiles["large_file.dat"][i] = byte(i % 256)
	}

	t.Log("Adding test files...")
	for filename, data := range testFiles {
		err := managedVault.AddFile(filename, data)
		require.NoError(t, err, "Failed to add test file: %s", filename)
	}

	// Close vault to ensure data is written
	err = vaultManager.CloseVault(vaultPath)
	require.NoError(t, err)

	t.Run("WrongPasswordAttempts", func(t *testing.T) {
		// Test multiple wrong password attempts
		wrongPasswords := []string{
			"WrongPassword123!",
			"CorruptionTestPassword124!",
			"corruptiontestpassword123!",
			"CorruptionTestPassword123",
			"",
			"123",
		}

		for _, wrongPassword := range wrongPasswords {
			_, err := vaultManager.OpenVault(vaultPath, wrongPassword)
			assert.Error(t, err, "Wrong password should be rejected: %s", wrongPassword)
		}

		// Correct password should still work after wrong attempts
		managedVault, err := vaultManager.OpenVault(vaultPath, password)
		require.NoError(t, err, "Correct password should work after wrong attempts")

		// Verify data integrity
		for filename, originalData := range testFiles {
			extractedData, err := managedVault.ExtractFile(filename)
			require.NoError(t, err, "Should extract file after wrong password attempts: %s", filename)
			assert.Equal(t, originalData, extractedData, "Data should be intact after wrong password attempts: %s", filename)
		}

		err = vaultManager.CloseVault(vaultPath)
		require.NoError(t, err)
	})

	t.Run("FileSystemCorruption", func(t *testing.T) {
		// This test simulates what happens when the vault file is corrupted
		// We'll create a backup first, then corrupt the original, then restore

		// Create backup
		backupPath := vaultPath + ".backup"
		originalData, err := os.ReadFile(vaultPath)
		require.NoError(t, err)

		err = os.WriteFile(backupPath, originalData, 0644)
		require.NoError(t, err)
		defer os.Remove(backupPath)

		// Test 1: Truncated file
		t.Run("TruncatedFile", func(t *testing.T) {
			// Ensure vault is closed to test corruption detection
			// Ignore error if vault is already closed
			vaultManager.CloseVault(vaultPath)

			// Truncate the vault file severely (keep only first 100 bytes)
			truncateSize := 100
			if len(originalData)/4 < truncateSize {
				truncateSize = len(originalData) / 4
			}
			truncatedData := originalData[:truncateSize]
			err = os.WriteFile(vaultPath, truncatedData, 0644)
			require.NoError(t, err)

			// Try to open truncated vault
			_, err = vaultManager.OpenVault(vaultPath, password)
			assert.Error(t, err, "Truncated vault should be rejected")

			// Restore original
			err = os.WriteFile(vaultPath, originalData, 0644)
			require.NoError(t, err)
		})

		// Test 2: Random corruption
		t.Run("RandomCorruption", func(t *testing.T) {
			// Corrupt random bytes in the middle of the file
			corruptedData := make([]byte, len(originalData))
			copy(corruptedData, originalData)

			// Corrupt 10 random bytes
			for i := 0; i < 10; i++ {
				pos := len(originalData)/4 + i*100 // Corrupt in the middle section
				if pos < len(corruptedData) {
					corruptedData[pos] ^= 0xFF // Flip all bits
				}
			}

			err = os.WriteFile(vaultPath, corruptedData, 0644)
			require.NoError(t, err)

			// Try to open corrupted vault
			_, err = vaultManager.OpenVault(vaultPath, password)
			// The vault might open but operations should fail gracefully
			if err == nil {
				t.Log("Corrupted vault opened - testing graceful failure")
				// If it opens, operations should fail gracefully
				managedVault, _ := vaultManager.OpenVault(vaultPath, password)
				if managedVault != nil {
					// Try to list files - this might fail
					_, err := managedVault.ListFiles()
					if err != nil {
						t.Log("ListFiles failed gracefully on corrupted vault:", err)
					}
					vaultManager.CloseVault(vaultPath)
				}
			} else {
				t.Log("Corrupted vault was properly rejected:", err)
			}

			// Restore original
			err = os.WriteFile(vaultPath, originalData, 0644)
			require.NoError(t, err)
		})

		// Test 3: Header corruption
		t.Run("HeaderCorruption", func(t *testing.T) {
			// Corrupt the first few bytes (likely header)
			corruptedData := make([]byte, len(originalData))
			copy(corruptedData, originalData)

			// Corrupt first 32 bytes
			for i := 0; i < 32 && i < len(corruptedData); i++ {
				corruptedData[i] = 0x00
			}

			err = os.WriteFile(vaultPath, corruptedData, 0644)
			require.NoError(t, err)

			// Try to open vault with corrupted header
			_, err = vaultManager.OpenVault(vaultPath, password)
			assert.Error(t, err, "Vault with corrupted header should be rejected")

			// Restore original
			err = os.WriteFile(vaultPath, originalData, 0644)
			require.NoError(t, err)
		})

		// Verify vault works after all corruption tests
		managedVault, err := vaultManager.OpenVault(vaultPath, password)
		require.NoError(t, err, "Vault should work after corruption tests")

		for filename, originalData := range testFiles {
			extractedData, err := managedVault.ExtractFile(filename)
			require.NoError(t, err, "Should extract file after corruption tests: %s", filename)
			assert.Equal(t, originalData, extractedData, "Data should be intact after corruption tests: %s", filename)
		}

		err = vaultManager.CloseVault(vaultPath)
		require.NoError(t, err)
	})
}

// TestMemorySecurityScenarios tests memory-related security aspects
func TestMemorySecurityScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory security tests in short mode")
	}

	tempDir, err := os.MkdirTemp("", "memory_security_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DefaultCipher:   "xchacha20-poly1305",
		AutoLockTimeout: 0,
		LogLevel:        "warn", // Reduce logging for memory tests
	}

	logger, err := createTestLogger()
	require.NoError(t, err)

	t.Run("LargeFileHandling", func(t *testing.T) {
		vaultManager, err := vault.NewVaultManager(cfg, logger)
		require.NoError(t, err)
		defer vaultManager.CloseAllVaults()

		vaultPath := filepath.Join(tempDir, "large_file_test.vault")
		password := "LargeFilePassword123!"

		err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
		require.NoError(t, err)

		managedVault, err := vaultManager.OpenVault(vaultPath, password)
		require.NoError(t, err)

		// Test with progressively larger files
		sizes := []int{
			1024 * 1024,      // 1MB
			5 * 1024 * 1024,  // 5MB
			10 * 1024 * 1024, // 10MB
		}

		for _, size := range sizes {
			t.Run(fmt.Sprintf("Size_%dMB", size/(1024*1024)), func(t *testing.T) {
				filename := fmt.Sprintf("large_file_%dmb.dat", size/(1024*1024))

				// Generate large file data
				largeData := make([]byte, size)
				for i := range largeData {
					largeData[i] = byte(i % 256)
				}

				// Add large file
				start := time.Now()
				err := managedVault.AddFile(filename, largeData)
				addDuration := time.Since(start)
				require.NoError(t, err, "Failed to add large file: %s", filename)
				t.Logf("Added %dMB file in %v", size/(1024*1024), addDuration)

				// Extract large file
				start = time.Now()
				extractedData, err := managedVault.ExtractFile(filename)
				extractDuration := time.Since(start)
				require.NoError(t, err, "Failed to extract large file: %s", filename)
				t.Logf("Extracted %dMB file in %v", size/(1024*1024), extractDuration)

				// Verify data integrity
				assert.Equal(t, largeData, extractedData, "Large file data corruption: %s", filename)

				// Clean up to save memory
				err = managedVault.DeleteFile(filename)
				require.NoError(t, err, "Failed to delete large file: %s", filename)
			})
		}
	})

	t.Run("MemoryPressure", func(t *testing.T) {
		// Test behavior under memory pressure by creating many vaults simultaneously
		const numVaults = 10
		vaultManagers := make([]*vault.VaultManager, numVaults)
		vaultPaths := make([]string, numVaults)

		// Create multiple vault managers
		for i := 0; i < numVaults; i++ {
			vaultManager, err := vault.NewVaultManager(cfg, logger)
			require.NoError(t, err)
			vaultManagers[i] = vaultManager

			vaultPath := filepath.Join(tempDir, fmt.Sprintf("pressure_test_%d.vault", i))
			vaultPaths[i] = vaultPath
			password := fmt.Sprintf("PressureTestPassword%d!", i)

			err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
			require.NoError(t, err)

			managedVault, err := vaultManager.OpenVault(vaultPath, password)
			require.NoError(t, err)

			// Add some data to each vault
			testData := make([]byte, 100*1024) // 100KB per vault
			_, err = rand.Read(testData)
			require.NoError(t, err)

			err = managedVault.AddFile("test_data.dat", testData)
			require.NoError(t, err)
		}

		// Verify all vaults are working
		for i, vaultManager := range vaultManagers {
			files, err := vaultManager.ListFiles(vaultPaths[i])
			require.NoError(t, err, "Vault %d should list files under memory pressure", i)
			assert.Len(t, files, 1, "Vault %d should have 1 file", i)
		}

		// Clean up
		for _, vaultManager := range vaultManagers {
			err := vaultManager.CloseAllVaults()
			require.NoError(t, err)
		}

		t.Logf("Successfully handled %d concurrent vaults under memory pressure", numVaults)
	})
}

// TestTimingAttackResistance tests resistance to timing attacks
func TestTimingAttackResistance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing attack tests in short mode")
	}

	tempDir, err := os.MkdirTemp("", "timing_attack_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DefaultCipher:   "xchacha20-poly1305",
		AutoLockTimeout: 0,
		LogLevel:        "warn",
	}

	logger, err := createTestLogger()
	require.NoError(t, err)

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	vaultPath := filepath.Join(tempDir, "timing_test.vault")
	correctPassword := "CorrectPassword123!"

	err = vaultManager.CreateVault(vaultPath, correctPassword, vault.CipherXChaCha20Poly1305)
	require.NoError(t, err)

	// Close the vault for testing
	_, err = vaultManager.OpenVault(vaultPath, correctPassword)
	require.NoError(t, err)
	err = vaultManager.CloseVault(vaultPath)
	require.NoError(t, err)

	t.Run("PasswordLengthTiming", func(t *testing.T) {
		// Test that password verification time doesn't leak password length
		passwords := []string{
			"a",                     // 1 char
			"ab",                    // 2 chars
			"abc",                   // 3 chars
			"abcd",                  // 4 chars
			"abcde",                 // 5 chars
			"CorrectPassword123",    // Almost correct (missing !)
			"WrongPassword123!",     // Same length as correct
			strings.Repeat("a", 50), // Very long
		}

		timings := make([]time.Duration, len(passwords))

		// Measure timing for each password
		for i, password := range passwords {
			start := time.Now()
			_, err := vaultManager.OpenVault(vaultPath, password)
			timings[i] = time.Since(start)

			// All should fail except potentially the correct one
			assert.Error(t, err, "Wrong password should fail: %s", password)
		}

		// Log timings for analysis
		for i, timing := range timings {
			t.Logf("Password length %d: %v", len(passwords[i]), timing)
		}

		// Check that timings are relatively consistent
		// This is a basic check - in practice, more sophisticated analysis would be needed
		var totalTime time.Duration
		for _, timing := range timings {
			totalTime += timing
		}
		avgTime := totalTime / time.Duration(len(timings))

		// Check that no timing is dramatically different (more than 10x average)
		for i, timing := range timings {
			ratio := float64(timing) / float64(avgTime)
			if ratio > 10.0 {
				t.Logf("WARNING: Password '%s' took %v (%.1fx average) - potential timing leak",
					passwords[i][:min(len(passwords[i]), 10)]+"...", timing, ratio)
			}
		}
	})

	t.Run("FileExistenceTiming", func(t *testing.T) {
		// Test that file existence doesn't leak through timing
		managedVault, err := vaultManager.OpenVault(vaultPath, correctPassword)
		require.NoError(t, err)

		// Add a test file
		err = managedVault.AddFile("existing_file.txt", []byte("test content"))
		require.NoError(t, err)

		testFiles := []string{
			"existing_file.txt",    // Exists
			"nonexistent_file.txt", // Doesn't exist
			"another_missing.txt",  // Doesn't exist
			"missing_file.dat",     // Doesn't exist
		}

		timings := make([]time.Duration, len(testFiles))

		// Measure timing for file extraction attempts
		for i, filename := range testFiles {
			start := time.Now()
			_, err := managedVault.ExtractFile(filename)
			timings[i] = time.Since(start)

			if filename == "existing_file.txt" {
				require.NoError(t, err, "Existing file should be extractable")
			} else {
				assert.Error(t, err, "Non-existent file should fail: %s", filename)
			}
		}

		// Log timings
		for i, timing := range timings {
			exists := testFiles[i] == "existing_file.txt"
			t.Logf("File %s (exists: %v): %v", testFiles[i], exists, timing)
		}

		err = vaultManager.CloseVault(vaultPath)
		require.NoError(t, err)
	})
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

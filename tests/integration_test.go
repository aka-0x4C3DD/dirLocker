package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultManagerIntegration tests the integration between Go layer and Rust core
func TestVaultManagerIntegration(t *testing.T) {
	// Setup test environment
	tempDir := t.TempDir()
	cfg := createTestConfig(tempDir)
	logger := logging.NewTestLogger()

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create vault manager: %v", err)
	}
	defer vaultManager.CloseAllVaults()

	vaultPath := filepath.Join(tempDir, "test.vault")
	password := "test-password-123"

	t.Run("CreateVault", func(t *testing.T) {
		err := vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
		require.NoError(t, err)

		// Verify vault file exists
		assert.FileExists(t, vaultPath)

		// Verify vault info
		info, err := vaultManager.GetVaultInfo(vaultPath)
		require.NoError(t, err)
		assert.Equal(t, vaultPath, info.Path)
		assert.True(t, info.Size > 0)
		assert.True(t, info.IsAccessible)
	})

	t.Run("OpenVault", func(t *testing.T) {
		managedVault, err := vaultManager.OpenVault(vaultPath, password)
		require.NoError(t, err)
		assert.NotNil(t, managedVault)

		// Verify vault is in open list
		openVaults := vaultManager.ListOpenVaults()
		assert.Contains(t, openVaults, vaultPath)

		// Verify vault info
		path, openedAt, lastUsed, isShared := managedVault.GetInfo()
		assert.Equal(t, vaultPath, path)
		assert.False(t, openedAt.IsZero())
		assert.False(t, lastUsed.IsZero())
		assert.False(t, isShared)
	})

	t.Run("GetVault", func(t *testing.T) {
		managedVault, exists := vaultManager.GetVault(vaultPath)
		assert.True(t, exists)
		assert.NotNil(t, managedVault)

		// Verify last used time is updated
		time.Sleep(10 * time.Millisecond)
		_, _, lastUsed1, _ := managedVault.GetInfo()

		managedVault.UpdateLastUsed()
		_, _, lastUsed2, _ := managedVault.GetInfo()

		assert.True(t, lastUsed2.After(lastUsed1))
	})

	t.Run("ChangePassword", func(t *testing.T) {
		newPassword := "new-password-456"

		err := vaultManager.ChangeVaultPassword(vaultPath, password, newPassword)
		require.NoError(t, err)

		// Verify old password no longer works
		err = vaultManager.CloseVault(vaultPath)
		require.NoError(t, err)

		_, err = vaultManager.OpenVault(vaultPath, password)
		assert.Error(t, err)

		// Verify new password works
		managedVault, err := vaultManager.OpenVault(vaultPath, newPassword)
		require.NoError(t, err)
		assert.NotNil(t, managedVault)

		password = newPassword // Update for subsequent tests
	})

	t.Run("GenerateRecoveryKey", func(t *testing.T) {
		recoveryKey, wrappedKey, err := vaultManager.GenerateRecoveryKey(vaultPath, password)
		require.NoError(t, err)
		assert.NotNil(t, recoveryKey)
		assert.NotNil(t, wrappedKey)

		// Verify recovery key can be converted to hex
		hexKey, err := recoveryKey.ToHex()
		require.NoError(t, err)
		assert.NotEmpty(t, hexKey)
		assert.Equal(t, 64, len(hexKey)) // 32 bytes = 64 hex chars

		// Verify recovery key can be parsed from hex
		parsedKey, err := vault.RecoveryKeyFromHex(hexKey)
		require.NoError(t, err)
		assert.Equal(t, recoveryKey.KeyData, parsedKey.KeyData)
	})

	t.Run("SharingOperations", func(t *testing.T) {
		// Generate sharing key pair
		keyPair, err := vault.GenerateSharingKeyPair()
		require.NoError(t, err)
		assert.NotNil(t, keyPair)

		managedVault, exists := vaultManager.GetVault(vaultPath)
		require.True(t, exists)

		// Add sharing recipient
		err = managedVault.Handle.AddSharingRecipient(keyPair.PublicKey)
		require.NoError(t, err)

		// Verify recipient count
		count, err := managedVault.Handle.SharingRecipientCount()
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Export sharing envelopes
		envelopes, err := managedVault.Handle.ExportSharingEnvelopes()
		require.NoError(t, err)
		assert.NotEmpty(t, envelopes)

		// Remove sharing recipient
		removed, err := managedVault.Handle.RemoveSharingRecipient(keyPair.PublicKey)
		require.NoError(t, err)
		assert.True(t, removed)

		// Verify recipient count is back to 0
		count, err = managedVault.Handle.SharingRecipientCount()
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("CloseVault", func(t *testing.T) {
		err := vaultManager.CloseVault(vaultPath)
		require.NoError(t, err)

		// Verify vault is no longer in open list
		openVaults := vaultManager.ListOpenVaults()
		assert.NotContains(t, openVaults, vaultPath)

		// Verify getting closed vault returns false
		_, exists := vaultManager.GetVault(vaultPath)
		assert.False(t, exists)
	})

	t.Run("CloseAllVaults", func(t *testing.T) {
		// Open multiple vaults
		vault1Path := filepath.Join(tempDir, "vault1.vault")
		vault2Path := filepath.Join(tempDir, "vault2.vault")

		err := vaultManager.CreateVault(vault1Path, password, vault.CipherAES256GCM)
		require.NoError(t, err)

		err = vaultManager.CreateVault(vault2Path, password, vault.CipherXChaCha20Poly1305)
		require.NoError(t, err)

		_, err = vaultManager.OpenVault(vault1Path, password)
		require.NoError(t, err)

		_, err = vaultManager.OpenVault(vault2Path, password)
		require.NoError(t, err)

		// Verify both vaults are open
		openVaults := vaultManager.ListOpenVaults()
		assert.Len(t, openVaults, 2)

		// Close all vaults
		err = vaultManager.CloseAllVaults()
		require.NoError(t, err)

		// Verify no vaults are open
		openVaults = vaultManager.ListOpenVaults()
		assert.Len(t, openVaults, 0)
	})
}

// TestCGOBindings tests the CGO bindings directly
func TestCGOBindings(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "cgo_test.vault")
	password := "cgo-test-password"

	t.Run("CreateAndOpenVault", func(t *testing.T) {
		// Create vault
		handle, err := vault.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
		require.NoError(t, err)
		assert.NotNil(t, handle)

		// Close immediately after creation
		err = handle.Close()
		require.NoError(t, err)

		// Open vault
		unlockMaterial := &vault.UnlockMaterial{Password: password}
		handle, err = vault.OpenVault(vaultPath, unlockMaterial)
		require.NoError(t, err)
		assert.NotNil(t, handle)

		// Close vault
		err = handle.Close()
		require.NoError(t, err)
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		unlockMaterial := &vault.UnlockMaterial{Password: "wrong-password"}
		handle, err := vault.OpenVault(vaultPath, unlockMaterial)
		assert.Error(t, err)
		assert.Nil(t, handle)

		// Verify error is of correct type
		vaultErr, ok := err.(*vault.VaultError)
		assert.True(t, ok)
		assert.Equal(t, vault.ErrorInvalidPassword, vaultErr.Code)
	})

	t.Run("NonexistentVault", func(t *testing.T) {
		nonexistentPath := filepath.Join(tempDir, "nonexistent.vault")
		unlockMaterial := &vault.UnlockMaterial{Password: password}

		handle, err := vault.OpenVault(nonexistentPath, unlockMaterial)
		assert.Error(t, err)
		assert.Nil(t, handle)
	})
}

// TestConfigurationIntegration tests configuration management
func TestConfigurationIntegration(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	t.Run("LoadDefaultConfig", func(t *testing.T) {
		cfg, err := config.LoadConfig(configPath)
		require.NoError(t, err)
		assert.NotNil(t, cfg)

		// Verify default values
		assert.Equal(t, "xchacha20poly1305", cfg.DefaultCipher)
		assert.Equal(t, 4*1024*1024, cfg.DefaultChunkSize)
		assert.Equal(t, "info", cfg.LogLevel)
		assert.True(t, cfg.SecureMemory)
		assert.True(t, cfg.ClearClipboard)

		// Verify config file was created
		assert.FileExists(t, configPath)
	})

	t.Run("SaveAndLoadConfig", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.DefaultCipher = "aes-256-gcm"
		cfg.LogLevel = "debug"
		cfg.AutoLockTimeout = 15 * time.Minute

		err := cfg.SaveToFile(configPath)
		require.NoError(t, err)

		// Load config and verify changes
		loadedCfg, err := config.LoadConfig(configPath)
		require.NoError(t, err)
		assert.Equal(t, "aes-256-gcm", loadedCfg.DefaultCipher)
		assert.Equal(t, "debug", loadedCfg.LogLevel)
		assert.Equal(t, 15*time.Minute, loadedCfg.AutoLockTimeout)
	})

	t.Run("ConfigValidation", func(t *testing.T) {
		cfg := config.DefaultConfig()

		// Test invalid cipher
		cfg.DefaultCipher = "invalid-cipher"
		err := cfg.Validate()
		require.NoError(t, err)
		assert.Equal(t, "xchacha20poly1305", cfg.DefaultCipher) // Should be reset to default

		// Test invalid chunk size
		cfg.DefaultChunkSize = 512 * 1024 // Too small
		err = cfg.Validate()
		require.NoError(t, err)
		assert.Equal(t, 1024*1024, cfg.DefaultChunkSize) // Should be reset to minimum

		// Test invalid log level
		cfg.LogLevel = "invalid-level"
		err = cfg.Validate()
		require.NoError(t, err)
		assert.Equal(t, "info", cfg.LogLevel) // Should be reset to default
	})
}

// TestLoggingIntegration tests secure logging functionality
func TestLoggingIntegration(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("SecureLogging", func(t *testing.T) {
		logFile := filepath.Join(tempDir, "secure_test.log")
		logConfig := &logging.LogConfig{
			Level:   "debug",
			File:    logFile,
			Console: false,
		}

		logger, err := logging.NewLogger(logConfig)
		require.NoError(t, err)

		// Test logging with sensitive data
		logger.Info("User login", "username", "testuser", "password", "secret123")
		logger.Debug("Vault operation", "path", "/test/vault.vault", "key", "deadbeef1234567890abcdef")
		logger.Error("Authentication failed", "token", "abc123def456", "error", "invalid credentials")

		// Close logger before reading file to ensure all data is flushed
		logger.Close()

		// Verify log file exists
		assert.FileExists(t, logFile)

		// Read log file and verify sensitive data is redacted
		logContent, err := os.ReadFile(logFile)
		require.NoError(t, err)

		logStr := string(logContent)
		assert.NotContains(t, logStr, "secret123")
		assert.NotContains(t, logStr, "deadbeef1234567890abcdef")
		assert.NotContains(t, logStr, "abc123def456")
		assert.Contains(t, logStr, "[REDACTED]")
	})

	t.Run("LogLevels", func(t *testing.T) {
		logConfig := &logging.LogConfig{
			Level:   "warn",
			File:    "",
			Console: false,
		}

		logger, err := logging.NewLogger(logConfig)
		require.NoError(t, err)
		defer logger.Close()

		// Verify log level is set correctly
		assert.Equal(t, "warning", logger.GetLevel())

		// Test setting log level
		err = logger.SetLevel("debug")
		require.NoError(t, err)
		assert.Equal(t, "debug", logger.GetLevel())

		// Test invalid log level
		err = logger.SetLevel("invalid")
		assert.Error(t, err)
	})
}

// TestErrorHandling tests error handling across the integration
func TestErrorHandling(t *testing.T) {
	tempDir := t.TempDir()
	cfg := createTestConfig(tempDir)
	logger := logging.NewTestLogger()

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create vault manager: %v", err)
	}
	defer vaultManager.CloseAllVaults()

	t.Run("InvalidVaultPath", func(t *testing.T) {
		// Test with invalid characters in path
		invalidPath := filepath.Join(tempDir, "invalid\x00path.vault")
		err := vaultManager.CreateVault(invalidPath, "password", vault.CipherAES256GCM)
		assert.Error(t, err)
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		vaultPath := filepath.Join(tempDir, "empty_pass.vault")
		_, err := vault.CreateVault(vaultPath, "", vault.CipherAES256GCM)
		assert.Error(t, err)
	})

	t.Run("DoubleClose", func(t *testing.T) {
		vaultPath := filepath.Join(tempDir, "double_close.vault")
		password := "test-password"

		// Create and open vault
		err := vaultManager.CreateVault(vaultPath, password, vault.CipherAES256GCM)
		require.NoError(t, err)

		managedVault, err := vaultManager.OpenVault(vaultPath, password)
		require.NoError(t, err)

		// Close vault twice
		err = managedVault.Handle.Close()
		require.NoError(t, err)

		_ = managedVault.Handle.Close()
		// Second close should not panic or cause issues
		// The exact behavior depends on implementation
	})
}

// Helper functions

func createTestConfig(tempDir string) *config.Config {
	cfg := config.DefaultConfig()
	cfg.ConfigDir = tempDir
	cfg.DataDir = tempDir
	cfg.TempDir = tempDir
	cfg.HiddenDir = filepath.Join(tempDir, "hidden")
	cfg.LogFile = filepath.Join(tempDir, "test.log")
	cfg.LogLevel = "debug"
	cfg.AutoLockTimeout = 1 * time.Minute
	return cfg
}

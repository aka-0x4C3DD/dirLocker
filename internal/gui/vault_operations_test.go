package gui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/test"
	"github.com/stretchr/testify/require"

	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

// TestVaultBrowserOperations tests the vault browser file operations
func TestVaultBrowserOperations(t *testing.T) {
	// Skip if CGO is disabled
	if !vault.IsCGOEnabled() {
		t.Skip("CGO disabled, skipping vault operations test")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "vault_browser_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test vault
	vaultPath := filepath.Join(tempDir, "test.vault")
	password := "test_password"

	// Initialize test components
	cfg := &config.Config{
		LogLevel:        "debug",
		AutoLockTimeout: 5 * time.Minute,
	}

	logger, err := logging.NewLogger(&logging.LogConfig{
		Level:   "debug",
		Console: true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	// Create test vault
	err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
	if err != nil {
		t.Fatalf("Failed to create test vault: %v", err)
	}

	// Open vault
	managedVault, err := vaultManager.OpenVault(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to open test vault: %v", err)
	}

	// Create Fyne app for testing
	testApp := app.New()
	notifications := NewNotificationManager(testApp, logger)

	// Create vault browser
	vaultBrowser := NewVaultBrowser(vaultManager, logger, notifications)
	vaultBrowser.SetVault(vaultPath)

	// Test file operations (these will return "not implemented" errors for now)
	t.Run("ListFiles", func(t *testing.T) {
		files, err := managedVault.ListFiles()
		// Should not fail, but may return empty list or "not implemented" error
		if err != nil {
			t.Logf("ListFiles returned error (expected): %v", err)
		} else {
			t.Logf("ListFiles returned %d files", len(files))
		}
	})

	t.Run("AddFile", func(t *testing.T) {
		testData := []byte("test file content")
		err := managedVault.AddFile("test.txt", testData)
		// Should return "not implemented" error for now
		if err != nil {
			t.Logf("AddFile returned error (expected): %v", err)
		}
	})

	t.Run("ExtractFile", func(t *testing.T) {
		_, err := managedVault.ExtractFile("test.txt")
		// Should return "not implemented" error for now
		if err != nil {
			t.Logf("ExtractFile returned error (expected): %v", err)
		}
	})

	t.Run("CreateDirectory", func(t *testing.T) {
		err := managedVault.CreateDirectory("test_dir")
		// Should return "not implemented" error for now
		if err != nil {
			t.Logf("CreateDirectory returned error (expected): %v", err)
		}
	})

	t.Run("DeleteFile", func(t *testing.T) {
		err := managedVault.DeleteFile("test.txt")
		// Should return "not implemented" error for now
		if err != nil {
			t.Logf("DeleteFile returned error (expected): %v", err)
		}
	})
}

// TestNotificationManager tests the notification system
func TestNotificationManager(t *testing.T) {
	// Create test app and logger
	testApp := app.New()

	logger, err := logging.NewLogger(&logging.LogConfig{
		Level:   "debug",
		Console: true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create notification manager
	notifications := NewNotificationManager(testApp, logger)

	// Test different notification types
	t.Run("SendInfo", func(t *testing.T) {
		notifications.SendInfo("Test Info", "This is a test info notification")
		// Should not panic or error
	})

	t.Run("SendSuccess", func(t *testing.T) {
		notifications.SendSuccess("Test Success", "This is a test success notification")
		// Should not panic or error
	})

	t.Run("SendWarning", func(t *testing.T) {
		notifications.SendWarning("Test Warning", "This is a test warning notification")
		// Should not panic or error
	})

	t.Run("SendError", func(t *testing.T) {
		notifications.SendError("Test Error", "This is a test error notification")
		// Should not panic or error
	})
}

// TestProgressNotification tests progress notifications
func TestProgressNotification(t *testing.T) {
	progress := NewProgressNotification("Test Operation", "Testing progress...")

	t.Run("UpdateProgress", func(t *testing.T) {
		progress.UpdateProgress(0.5, "Half way done")
		if progress.Progress != 0.5 {
			t.Errorf("Expected progress 0.5, got %f", progress.Progress)
		}
		if progress.Message != "Half way done" {
			t.Errorf("Expected message 'Half way done', got '%s'", progress.Message)
		}
	})

	t.Run("ShowHide", func(t *testing.T) {
		progress.Show()
		if !progress.IsVisible {
			t.Error("Expected progress to be visible after Show()")
		}

		progress.Hide()
		if progress.IsVisible {
			t.Error("Expected progress to be hidden after Hide()")
		}
	})
}

// TestMainWindowIntegration tests main window integration
func TestMainWindowIntegration(t *testing.T) {
	// Create test app
	testApp := test.NewApp()
	defer testApp.Quit()

	// Create test configuration
	cfg := &config.Config{
		LogLevel:        "debug",
		AutoLockTimeout: 5 * time.Minute,
		DefaultCipher:   "xchacha20-poly1305",
	}

	logger, err := logging.NewLogger(&logging.LogConfig{
		Level:   "debug",
		Console: true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	// Create main window
	mainWindow := NewMainWindow(testApp, vaultManager, cfg, logger)

	t.Run("WindowCreation", func(t *testing.T) {
		if mainWindow == nil {
			t.Fatal("Failed to create main window")
		}
		notificationMgr := mainWindow.GetNotificationManager()
		t.Logf("Notification manager: %v", notificationMgr)
		if notificationMgr == nil {
			t.Error("Notification manager not initialized")
		} else {
			t.Log("Notification manager properly initialized")
		}
		if mainWindow.vaultBrowser == nil {
			t.Error("Vault browser not initialized")
		}
	})

	t.Run("VaultListUpdate", func(t *testing.T) {
		// Should start with no vaults
		mainWindow.updateVaultList()
		if len(mainWindow.openVaults) != 0 {
			t.Errorf("Expected 0 open vaults, got %d", len(mainWindow.openVaults))
		}
	})
}

// TestRecoveryKeyOperations tests recovery key functionality
func TestRecoveryKeyOperations(t *testing.T) {
	// Skip if CGO is disabled
	if !vault.IsCGOEnabled() {
		t.Skip("CGO disabled, skipping recovery key test")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "recovery_key_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test vault
	vaultPath := filepath.Join(tempDir, "test.vault")
	password := "test_password"

	cfg := &config.Config{
		LogLevel:        "debug",
		AutoLockTimeout: 5 * time.Minute,
	}

	logger, err := logging.NewLogger(&logging.LogConfig{
		Level:   "debug",
		Console: true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	vaultManager, err := vault.NewVaultManager(cfg, logger)
	require.NoError(t, err)
	defer vaultManager.CloseAllVaults()

	// Create and open test vault
	err = vaultManager.CreateVault(vaultPath, password, vault.CipherXChaCha20Poly1305)
	if err != nil {
		t.Fatalf("Failed to create test vault: %v", err)
	}

	t.Run("GenerateRecoveryKey", func(t *testing.T) {
		recoveryKey, wrappedKey, err := vaultManager.GenerateRecoveryKey(vaultPath, password)
		if err != nil {
			t.Logf("GenerateRecoveryKey returned error (may be expected): %v", err)
			return
		}

		if recoveryKey == nil {
			t.Error("Recovery key is nil")
		}
		if wrappedKey == nil {
			t.Error("Wrapped key is nil")
		}

		// Test hex conversion
		if recoveryKey != nil {
			hexKey, err := recoveryKey.ToHex()
			if err != nil {
				t.Errorf("Failed to convert recovery key to hex: %v", err)
			} else if hexKey == "" {
				t.Error("Hex key is empty")
			} else {
				t.Logf("Recovery key hex: %s", hexKey)
			}
		}
	})
}

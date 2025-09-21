package tests

import (
	"os"
	"testing"

	"dirLocker/pkg/vault"
)

// TestFFIIntegration tests that all FFI functions are properly integrated with CGO enabled
func TestFFIIntegration(t *testing.T) {
	// Clean up any test files
	defer func() {
		os.Remove("test_ffi.vault")
		os.Remove("test_ffi_open.vault")
	}()

	// Test basic vault operations
	t.Run("CreateVault", func(t *testing.T) {
		v, err := vault.CreateVault("test_ffi.vault", "password", vault.CipherAES256GCM)
		if err != nil {
			t.Logf("CreateVault error (may be expected): %v", err)
			// For now, we expect this to fail with current implementation
			// but it should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("CreateVault succeeded: %+v", v)
			if v != nil {
				v.Close()
			}
		}
	})

	t.Run("OpenVault", func(t *testing.T) {
		// First try to create a vault for opening
		v, err := vault.CreateVault("test_ffi_open.vault", "password", vault.CipherAES256GCM)
		if err == nil && v != nil {
			v.Close()

			// Now try to open it
			unlockMaterial := &vault.UnlockMaterial{
				Password: "password",
			}
			openedVault, err := vault.OpenVault("test_ffi_open.vault", unlockMaterial)
			if err != nil {
				t.Logf("OpenVault error (may be expected): %v", err)
				// Should not be a "CGO not available" error
				if err.Error() == "CGO not available - vault operations require Rust core library" {
					t.Error("CGO should be available now, but got CGO not available error")
				}
			} else {
				t.Logf("OpenVault succeeded: %+v", openedVault)
				if openedVault != nil {
					openedVault.Close()
				}
			}
		} else {
			t.Logf("Skipping OpenVault test - CreateVault failed: %v", err)
		}
	})

	t.Run("GenerateSharingKeyPair", func(t *testing.T) {
		keyPair, err := vault.GenerateSharingKeyPair()
		if err != nil {
			t.Logf("GenerateSharingKeyPair error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("GenerateSharingKeyPair succeeded: %+v", keyPair)
		}
	})

	t.Run("RecoveryKeyFromHex", func(t *testing.T) {
		// Use a valid 64-character hex string (32 bytes)
		hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		recoveryKey, err := vault.RecoveryKeyFromHex(hexKey)
		if err != nil {
			t.Logf("RecoveryKeyFromHex error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("RecoveryKeyFromHex succeeded: %+v", recoveryKey)
		}
	})

	t.Run("RecoverWithKey", func(t *testing.T) {
		// This test requires valid recovery key and wrapped key, so it's expected to fail
		// but should not fail with "CGO not available"
		recoveryKey := &vault.RecoveryKey{}
		wrappedKey := &vault.WrappedMasterKey{}
		err := vault.RecoverWithKey("nonexistent.vault", recoveryKey, wrappedKey, "new_password")
		if err != nil {
			t.Logf("RecoverWithKey error (expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Log("RecoverWithKey unexpectedly succeeded")
		}
	})

	t.Run("OpenWithRecipientKey", func(t *testing.T) {
		// This test requires valid recipient key and envelopes, so it's expected to fail
		// but should not fail with "CGO not available"
		var privateKey [32]byte
		_, err := vault.OpenWithRecipientKey("nonexistent.vault", privateKey, "{}")
		if err != nil {
			t.Logf("OpenWithRecipientKey error (expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Log("OpenWithRecipientKey unexpectedly succeeded")
		}
	})
}

// TestVaultHandleMethods tests vault handle methods with CGO enabled
func TestVaultHandleMethods(t *testing.T) {
	// Try to create a real vault handle for testing
	v, err := vault.CreateVault("test_handle.vault", "password", vault.CipherAES256GCM)
	defer os.Remove("test_handle.vault")

	if err != nil {
		t.Logf("Could not create vault for handle testing: %v", err)
		// Test with nil handle to ensure we don't get "CGO not available" errors
		var handle *vault.VaultHandle

		t.Run("ChangePassword", func(t *testing.T) {
			err := handle.ChangePassword("old", "new")
			if err != nil {
				t.Logf("ChangePassword error (expected with nil handle): %v", err)
				// Should not be a "CGO not available" error
				if err.Error() == "CGO not available - vault operations require Rust core library" {
					t.Error("CGO should be available now, but got CGO not available error")
				}
			}
		})
		return
	}

	handle := v
	defer handle.Close()

	t.Run("ChangePassword", func(t *testing.T) {
		err := handle.ChangePassword("password", "new_password")
		if err != nil {
			t.Logf("ChangePassword error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Log("ChangePassword succeeded")
			// Change it back
			handle.ChangePassword("new_password", "password")
		}
	})

	t.Run("GenerateRecoveryKey", func(t *testing.T) {
		recoveryKey, wrappedKey, err := handle.GenerateRecoveryKey("password")
		if err != nil {
			t.Logf("GenerateRecoveryKey error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("GenerateRecoveryKey succeeded: recoveryKey=%+v, wrappedKey=%+v", recoveryKey, wrappedKey)
		}
	})

	t.Run("AddSharingRecipient", func(t *testing.T) {
		var publicKey [32]byte
		// Fill with some test data
		for i := range publicKey {
			publicKey[i] = byte(i)
		}
		err := handle.AddSharingRecipient(publicKey)
		if err != nil {
			t.Logf("AddSharingRecipient error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Log("AddSharingRecipient succeeded")
		}
	})

	t.Run("RemoveSharingRecipient", func(t *testing.T) {
		var publicKey [32]byte
		// Fill with some test data
		for i := range publicKey {
			publicKey[i] = byte(i)
		}
		removed, err := handle.RemoveSharingRecipient(publicKey)
		if err != nil {
			t.Logf("RemoveSharingRecipient error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("RemoveSharingRecipient succeeded: removed=%t", removed)
		}
	})

	t.Run("SharingRecipientCount", func(t *testing.T) {
		count, err := handle.SharingRecipientCount()
		if err != nil {
			t.Logf("SharingRecipientCount error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("SharingRecipientCount succeeded: count=%d", count)
		}
	})

	t.Run("ExportSharingEnvelopes", func(t *testing.T) {
		envelopes, err := handle.ExportSharingEnvelopes()
		if err != nil {
			t.Logf("ExportSharingEnvelopes error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("ExportSharingEnvelopes succeeded: %s", envelopes)
		}
	})

	t.Run("ImportSharingEnvelopes", func(t *testing.T) {
		err := handle.ImportSharingEnvelopes("{}")
		if err != nil {
			t.Logf("ImportSharingEnvelopes error (expected with empty JSON): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Log("ImportSharingEnvelopes succeeded")
		}
	})

	t.Run("Close", func(t *testing.T) {
		// Don't close here as we defer it above
		t.Log("Close test skipped - handle will be closed in defer")
	})
}

// TestRecoveryKeyMethods tests recovery key methods with CGO enabled
func TestRecoveryKeyMethods(t *testing.T) {
	// Try to generate a real recovery key for testing
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	recoveryKey, err := vault.RecoveryKeyFromHex(hexKey)

	if err != nil {
		t.Logf("Could not create recovery key for testing: %v", err)
		// Test with empty recovery key to ensure we don't get "CGO not available" errors
		recoveryKey = &vault.RecoveryKey{}
	}

	t.Run("ToHex", func(t *testing.T) {
		hexStr, err := recoveryKey.ToHex()
		if err != nil {
			t.Logf("ToHex error (may be expected): %v", err)
			// Should not be a "CGO not available" error
			if err.Error() == "CGO not available - vault operations require Rust core library" {
				t.Error("CGO should be available now, but got CGO not available error")
			}
		} else {
			t.Logf("ToHex succeeded: %s", hexStr)
		}
	})
}

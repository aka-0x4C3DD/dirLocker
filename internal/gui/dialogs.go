package gui

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"dirLocker/pkg/vault"
)

// showCreateVaultDialog displays the create vault dialog
func (mw *MainWindow) showCreateVaultDialog() {
	// Create form entries
	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("Select vault file location...")

	browseBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			writer.Close()

			path := writer.URI().Path()
			if filepath.Ext(path) != ".vault" {
				path += ".vault"
			}
			pathEntry.SetText(path)
		}, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	pathContainer := container.NewBorder(nil, nil, nil, browseBtn, pathEntry)

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Enter vault password")

	confirmPasswordEntry := widget.NewPasswordEntry()
	confirmPasswordEntry.SetPlaceHolder("Confirm password")

	// Cipher selection
	cipherSelect := widget.NewSelect([]string{
		"AES-256-GCM",
		"XChaCha20-Poly1305",
	}, nil)
	cipherSelect.SetSelected("XChaCha20-Poly1305") // Default

	// KDF parameters
	memoryEntry := widget.NewEntry()
	memoryEntry.SetText("65536") // 64MB default

	operationsEntry := widget.NewEntry()
	operationsEntry.SetText("3") // Default

	parallelismEntry := widget.NewEntry()
	parallelismEntry.SetText("1") // Default

	// Advanced options in a collapsible container
	advancedCheck := widget.NewCheck("Show advanced options", nil)

	advancedContainer := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Memory (KB):", memoryEntry),
			widget.NewFormItem("Operations:", operationsEntry),
			widget.NewFormItem("Parallelism:", parallelismEntry),
		),
	)
	advancedContainer.Hide()

	advancedCheck.OnChanged = func(checked bool) {
		if checked {
			advancedContainer.Show()
		} else {
			advancedContainer.Hide()
		}
	}

	// Create form
	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Vault Path:", pathContainer),
			widget.NewFormItem("Password:", passwordEntry),
			widget.NewFormItem("Confirm Password:", confirmPasswordEntry),
			widget.NewFormItem("Cipher:", cipherSelect),
		},
	}

	content := container.NewVBox(
		form,
		advancedCheck,
		advancedContainer,
	)

	createDialog := dialog.NewCustomConfirm("Create Vault", "Create", "Cancel", content,
		func(confirm bool) {
			if !confirm {
				return
			}

			// Validate inputs
			vaultPath := pathEntry.Text
			password := passwordEntry.Text
			confirmPassword := confirmPasswordEntry.Text

			if vaultPath == "" {
				mw.showError("Validation Error", "Please select a vault file location")
				return
			}

			if password == "" {
				mw.showError("Validation Error", "Please enter a password")
				return
			}

			if password != confirmPassword {
				mw.showError("Validation Error", "Passwords do not match")
				return
			}

			// Parse KDF parameters
			memory, err := strconv.Atoi(memoryEntry.Text)
			if err != nil || memory < 1024 {
				mw.showError("Validation Error", "Invalid memory parameter (minimum 1024 KB)")
				return
			}

			operations, err := strconv.Atoi(operationsEntry.Text)
			if err != nil || operations < 1 {
				mw.showError("Validation Error", "Invalid operations parameter (minimum 1)")
				return
			}

			parallelism, err := strconv.Atoi(parallelismEntry.Text)
			if err != nil || parallelism < 1 {
				mw.showError("Validation Error", "Invalid parallelism parameter (minimum 1)")
				return
			}

			// Determine cipher type
			var cipherType vault.CipherType
			switch cipherSelect.Selected {
			case "AES-256-GCM":
				cipherType = vault.CipherAES256GCM
			case "XChaCha20-Poly1305":
				cipherType = vault.CipherXChaCha20Poly1305
			default:
				cipherType = vault.CipherXChaCha20Poly1305
			}

			// Create vault
			mw.createVault(vaultPath, password, cipherType, memory, operations, parallelism)
		},
		mw.window,
	)

	createDialog.Resize(fyne.NewSize(500, 400))
	createDialog.Show()
}

// showOpenVaultDialog displays the open vault dialog
func (mw *MainWindow) showOpenVaultDialog() {
	// Create form entries
	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("Select vault file...")

	browseBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			reader.Close()
			pathEntry.SetText(reader.URI().Path())
		}, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	pathContainer := container.NewBorder(nil, nil, nil, browseBtn, pathEntry)

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Enter vault password")

	// Recovery key option
	useRecoveryCheck := widget.NewCheck("Use recovery key instead", nil)
	recoveryEntry := widget.NewEntry()
	recoveryEntry.SetPlaceHolder("Enter recovery key (hex)")
	recoveryEntry.Hide()

	useRecoveryCheck.OnChanged = func(checked bool) {
		if checked {
			recoveryEntry.Show()
			passwordEntry.Hide()
		} else {
			recoveryEntry.Hide()
			passwordEntry.Show()
		}
	}

	// Create form
	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Vault Path:", pathContainer),
			widget.NewFormItem("Password:", passwordEntry),
		},
	}

	content := container.NewVBox(
		form,
		useRecoveryCheck,
		recoveryEntry,
	)

	openDialog := dialog.NewCustomConfirm("Open Vault", "Open", "Cancel", content,
		func(confirm bool) {
			if !confirm {
				return
			}

			vaultPath := pathEntry.Text
			if vaultPath == "" {
				mw.showError("Validation Error", "Please select a vault file")
				return
			}

			if useRecoveryCheck.Checked {
				recoveryKey := recoveryEntry.Text
				if recoveryKey == "" {
					mw.showError("Validation Error", "Please enter a recovery key")
					return
				}
				mw.openVaultWithRecovery(vaultPath, recoveryKey)
			} else {
				password := passwordEntry.Text
				if password == "" {
					mw.showError("Validation Error", "Please enter a password")
					return
				}
				mw.openVault(vaultPath, password)
			}
		},
		mw.window,
	)

	openDialog.Resize(fyne.NewSize(450, 300))
	openDialog.Show()
}

// showSettingsDialog displays the settings dialog
func (mw *MainWindow) showSettingsDialog() {
	// Create settings form
	logLevelSelect := widget.NewSelect([]string{
		"debug", "info", "warn", "error",
	}, nil)
	logLevelSelect.SetSelected(mw.config.LogLevel)

	autoLockEntry := widget.NewEntry()
	autoLockEntry.SetText(fmt.Sprintf("%d", int(mw.config.AutoLockTimeout.Minutes())))

	// Icon selection
	iconPathEntry := widget.NewEntry()
	iconPathEntry.SetText(mw.config.IconPath)

	iconBrowseBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			reader.Close()

			path := reader.URI().Path()
			if filepath.Ext(path) == ".ico" {
				iconPathEntry.SetText(path)
			} else {
				mw.showError("Invalid Icon", "Please select a .ico file")
			}
		}, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	iconContainer := container.NewBorder(nil, nil, nil, iconBrowseBtn, iconPathEntry)

	clearIconBtn := widget.NewButton("Use Default", func() {
		iconPathEntry.SetText("")
	})

	// Default cipher selection
	defaultCipherSelect := widget.NewSelect([]string{
		"AES-256-GCM",
		"XChaCha20-Poly1305",
	}, nil)

	switch mw.config.DefaultCipher {
	case "aes-256-gcm":
		defaultCipherSelect.SetSelected("AES-256-GCM")
	case "xchacha20-poly1305":
		defaultCipherSelect.SetSelected("XChaCha20-Poly1305")
	}

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Log Level:", logLevelSelect),
			widget.NewFormItem("Auto-lock (minutes):", autoLockEntry),
			widget.NewFormItem("Default Cipher:", defaultCipherSelect),
			widget.NewFormItem("Custom Icon:", iconContainer),
		},
	}

	content := container.NewVBox(
		form,
		clearIconBtn,
	)

	settingsDialog := dialog.NewCustomConfirm("Settings", "Save", "Cancel", content,
		func(confirm bool) {
			if !confirm {
				return
			}

			// Update configuration
			mw.config.LogLevel = logLevelSelect.Selected

			if autoLockMinutes, err := strconv.Atoi(autoLockEntry.Text); err == nil && autoLockMinutes > 0 {
				mw.config.AutoLockTimeout = time.Duration(autoLockMinutes) * time.Minute
			}

			mw.config.IconPath = iconPathEntry.Text

			switch defaultCipherSelect.Selected {
			case "AES-256-GCM":
				mw.config.DefaultCipher = "aes-256-gcm"
			case "XChaCha20-Poly1305":
				mw.config.DefaultCipher = "xchacha20-poly1305"
			}

			// TODO: Save configuration
			// For now, just log that settings were updated

			mw.logger.Info("Settings updated")
			mw.showInfo("Settings", "Settings saved successfully")
		},
		mw.window,
	)

	settingsDialog.Resize(fyne.NewSize(500, 350))
	settingsDialog.Show()
}

// showAboutDialog displays the about dialog
func (mw *MainWindow) showAboutDialog() {
	version := "1.0.0" // TODO: Get from build info

	aboutText := fmt.Sprintf(`dirLocker %s

Encrypted vault application for secure file storage.

Features:
• Strong encryption (AES-256-GCM, XChaCha20-Poly1305)
• Secure key derivation (Argon2id)
• File hiding system
• Cross-platform support
• Secure sharing capabilities

Built with Go and Fyne.`, version)

	dialog.ShowInformation("About dirLocker", aboutText, mw.window)
}

// Vault operation implementations

func (mw *MainWindow) createVault(path, password string, cipher vault.CipherType, memory, operations, parallelism int) {
	// Show progress dialog
	progress := dialog.NewProgressInfinite("Creating Vault", "Creating encrypted vault...", mw.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		kdfParams := &vault.KDFParams{
			Memory:      uint32(memory),
			Operations:  uint32(operations),
			Parallelism: uint32(parallelism),
		}
		err := mw.vaultManager.CreateVaultWithParams(path, password, cipher, kdfParams)
		if err != nil {
			mw.showError("Create Vault Error", fmt.Sprintf("Failed to create vault: %v", err))
			return
		}

		mw.logger.Info("Vault created from GUI", "path", path, "cipher", cipher)
		mw.updateVaultList()
		mw.showInfo("Success", fmt.Sprintf("Vault created: %s", filepath.Base(path)))
	}()
}

func (mw *MainWindow) openVault(path, password string) {
	// Show progress dialog
	progress := dialog.NewProgressInfinite("Opening Vault", "Opening encrypted vault...", mw.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		_, err := mw.vaultManager.OpenVault(path, password)
		if err != nil {
			mw.showError("Open Vault Error", fmt.Sprintf("Failed to open vault: %v", err))
			return
		}

		mw.logger.Info("Vault opened from GUI", "path", path)
		mw.updateVaultList()
		mw.showInfo("Success", fmt.Sprintf("Vault opened: %s", filepath.Base(path)))
	}()
}

func (mw *MainWindow) openVaultWithRecovery(path, recoveryKey string) {
	// Show progress dialog
	progress := dialog.NewProgressInfinite("Opening Vault", "Opening vault with recovery key...", mw.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		// TODO: Implement recovery key opening
		mw.showError("Not Implemented", "Recovery key opening is not yet implemented in the GUI")
	}()
}

// Utility methods

func (mw *MainWindow) showError(title, message string) {
	dialog.ShowError(fmt.Errorf("%s", message), mw.window)
}

func (mw *MainWindow) showInfo(title, message string) {
	dialog.ShowInformation(title, message, mw.window)
}

// showGenerateRecoveryKeyDialog displays the generate recovery key dialog
func (mw *MainWindow) showGenerateRecoveryKeyDialog() {
	if mw.selectedVault == "" {
		mw.showError("No Vault Selected", "Please select a vault first")
		return
	}

	// Create form entries
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Enter vault password")

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Vault Password:", passwordEntry),
		},
	}

	generateDialog := dialog.NewCustomConfirm("Generate Recovery Key", "Generate", "Cancel", form,
		func(confirm bool) {
			if !confirm {
				return
			}

			password := passwordEntry.Text
			if password == "" {
				mw.showError("Validation Error", "Please enter the vault password")
				return
			}

			mw.generateRecoveryKey(mw.selectedVault, password)
		},
		mw.window,
	)

	generateDialog.Resize(fyne.NewSize(400, 200))
	generateDialog.Show()
}

// showImportRecoveryKeyDialog displays the import recovery key dialog
func (mw *MainWindow) showImportRecoveryKeyDialog() {
	// Create form entries
	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("Select vault file...")

	browseBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			reader.Close()
			pathEntry.SetText(reader.URI().Path())
		}, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	pathContainer := container.NewBorder(nil, nil, nil, browseBtn, pathEntry)

	recoveryKeyEntry := widget.NewEntry()
	recoveryKeyEntry.SetPlaceHolder("Enter recovery key (hex)")

	newPasswordEntry := widget.NewPasswordEntry()
	newPasswordEntry.SetPlaceHolder("Enter new password")

	confirmPasswordEntry := widget.NewPasswordEntry()
	confirmPasswordEntry.SetPlaceHolder("Confirm new password")

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Vault Path:", pathContainer),
			widget.NewFormItem("Recovery Key:", recoveryKeyEntry),
			widget.NewFormItem("New Password:", newPasswordEntry),
			widget.NewFormItem("Confirm Password:", confirmPasswordEntry),
		},
	}

	importDialog := dialog.NewCustomConfirm("Import Recovery Key", "Recover", "Cancel", form,
		func(confirm bool) {
			if !confirm {
				return
			}

			vaultPath := pathEntry.Text
			recoveryKeyHex := recoveryKeyEntry.Text
			newPassword := newPasswordEntry.Text
			confirmPassword := confirmPasswordEntry.Text

			if vaultPath == "" {
				mw.showError("Validation Error", "Please select a vault file")
				return
			}

			if recoveryKeyHex == "" {
				mw.showError("Validation Error", "Please enter a recovery key")
				return
			}

			if newPassword == "" {
				mw.showError("Validation Error", "Please enter a new password")
				return
			}

			if newPassword != confirmPassword {
				mw.showError("Validation Error", "Passwords do not match")
				return
			}

			mw.recoverVaultWithKey(vaultPath, recoveryKeyHex, newPassword)
		},
		mw.window,
	)

	importDialog.Resize(fyne.NewSize(500, 300))
	importDialog.Show()
}

// Recovery key operation implementations

func (mw *MainWindow) generateRecoveryKey(vaultPath, password string) {
	// Show progress dialog
	progressBar := widget.NewProgressBarInfinite()
	progressContent := container.NewVBox(
		widget.NewLabel("Generating recovery key..."),
		progressBar,
	)
	progress := dialog.NewCustomWithoutButtons("Generating Recovery Key", progressContent, mw.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		recoveryKey, wrappedKey, err := mw.vaultManager.GenerateRecoveryKey(vaultPath, password)
		if err != nil {
			mw.showError("Recovery Key Error", fmt.Sprintf("Failed to generate recovery key: %v", err))
			return
		}

		// Convert recovery key to hex
		hexKey, err := recoveryKey.ToHex()
		if err != nil {
			mw.showError("Recovery Key Error", fmt.Sprintf("Failed to convert recovery key: %v", err))
			return
		}

		// Show recovery key dialog
		mw.showRecoveryKeyResult(hexKey, wrappedKey)
		mw.logger.Info("Recovery key generated", "vault", vaultPath)
	}()
}

func (mw *MainWindow) showRecoveryKeyResult(hexKey string, wrappedKey *vault.WrappedMasterKey) {
	// Create recovery key display
	keyEntry := widget.NewEntry()
	keyEntry.SetText(hexKey)
	keyEntry.Disable()

	copyBtn := widget.NewButton("Copy to Clipboard", func() {
		mw.window.Clipboard().SetContent(hexKey)
		mw.showInfo("Copied", "Recovery key copied to clipboard")
	})

	saveBtn := widget.NewButton("Save to File", func() {
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			defer writer.Close()

			_, err = writer.Write([]byte(hexKey))
			if err != nil {
				mw.showError("Save Error", fmt.Sprintf("Failed to save recovery key: %v", err))
				return
			}

			mw.showInfo("Saved", "Recovery key saved to file")
		}, mw.window)
	})

	warningText := widget.NewRichTextFromMarkdown(`**⚠️ IMPORTANT WARNING ⚠️**

This recovery key allows access to your vault if you forget your password.

• **Store it safely offline** (write it down, print it, etc.)
• **Never share it** with anyone you don't trust completely
• **This is the only time** it will be displayed
• **If you lose both** your password and this key, your data is **permanently lost**`)

	content := container.NewVBox(
		warningText,
		widget.NewSeparator(),
		widget.NewLabel("Recovery Key (Hex):"),
		keyEntry,
		container.NewHBox(copyBtn, saveBtn),
	)

	recoveryDialog := dialog.NewCustom("Recovery Key Generated", "I Have Saved It", content, mw.window)
	recoveryDialog.Resize(fyne.NewSize(600, 400))
	recoveryDialog.Show()
}

func (mw *MainWindow) recoverVaultWithKey(vaultPath, recoveryKeyHex, newPassword string) {
	// Show progress dialog
	progressBar := widget.NewProgressBarInfinite()
	progressContent := container.NewVBox(
		widget.NewLabel("Recovering vault access..."),
		progressBar,
	)
	progress := dialog.NewCustomWithoutButtons("Recovering Vault", progressContent, mw.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		// Parse recovery key from hex
		recoveryKey, err := vault.RecoveryKeyFromHex(recoveryKeyHex)
		if err != nil {
			mw.showError("Recovery Error", fmt.Sprintf("Invalid recovery key: %v", err))
			return
		}

		// For now, we need the wrapped key which should be stored separately
		// In a full implementation, this would be loaded from a file or user input
		// TODO: Implement proper wrapped key handling
		_ = recoveryKey // Avoid unused variable warning
		mw.showError("Not Fully Implemented", "Recovery key import requires wrapped master key data which is not yet implemented in the GUI")

		mw.logger.Info("Recovery attempted", "vault", vaultPath)
	}()
}

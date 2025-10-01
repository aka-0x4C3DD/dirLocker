package gui

import (
	"fmt"
	"path/filepath"
	"runtime"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// mountSelectedVault mounts the currently selected vault
func (mw *MainWindow) mountSelectedVault() {
	if mw.selectedVault == "" {
		mw.showError("Mount Error", "Please select a vault to mount")
		return
	}

	// Check if vault exists
	_, exists := mw.vaultManager.GetVault(mw.selectedVault)
	if !exists {
		mw.showError("Mount Error", "Vault not found")
		return
	}

	// TODO: Check if vault is mounted - IsMounted method needs to be implemented
	// For now, just proceed to mount dialog

	// Show mount point selection dialog
	mw.showMountPointDialog()
}

// unmountSelectedVault unmounts the currently selected vault
func (mw *MainWindow) unmountSelectedVault() {
	if mw.selectedVault == "" {
		mw.showError("Unmount Error", "Please select a vault to unmount")
		return
	}

	// Check if vault exists
	_, exists := mw.vaultManager.GetVault(mw.selectedVault)
	if !exists {
		mw.showError("Unmount Error", "Vault not found")
		return
	}

	// TODO: Check if vault is mounted - IsMounted method needs to be implemented
	// For now, just proceed to unmount

	// Show confirmation dialog
	vaultName := filepath.Base(mw.selectedVault)
	dialog.ShowConfirm("Unmount Vault",
		fmt.Sprintf("Are you sure you want to unmount '%s'?\n\nThis will close the mounted filesystem and secure the vault contents.", vaultName),
		func(confirm bool) {
			if confirm {
				mw.performUnmount()
			}
		},
		mw.window,
	)
}

// showMountPointDialog displays the mount point selection dialog
func (mw *MainWindow) showMountPointDialog() {
	vaultName := filepath.Base(mw.selectedVault)

	// Create mount point entry
	mountPointEntry := widget.NewEntry()

	// Set default mount point based on platform
	var defaultMountPoint string
	switch runtime.GOOS {
	case "windows":
		defaultMountPoint = "V:" // Default to V: drive on Windows
	case "darwin":
		defaultMountPoint = fmt.Sprintf("/Volumes/%s", vaultName)
	default: // Linux and others
		defaultMountPoint = fmt.Sprintf("/mnt/%s", vaultName)
	}
	mountPointEntry.SetText(defaultMountPoint)

	// Browse button for mount point selection
	browseBtn := widget.NewButton("Browse...", func() {
		if runtime.GOOS == "windows" {
			// On Windows, show drive letter selection
			mw.showDriveLetterDialog(mountPointEntry)
		} else {
			// On Unix systems, show folder selection
			dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
				if err != nil || uri == nil {
					return
				}
				mountPointEntry.SetText(uri.Path())
			}, mw.window)
		}
	})

	// Platform-specific instructions
	var instructions string
	switch runtime.GOOS {
	case "windows":
		instructions = "Select a drive letter (e.g., V:) to mount the vault.\nRequires Dokany or WinFSP to be installed."
	case "darwin":
		instructions = "Select a mount point directory.\nRequires macFUSE to be installed."
	default:
		instructions = "Select a mount point directory.\nRequires FUSE to be installed."
	}

	instructionLabel := widget.NewLabel(instructions)
	instructionLabel.Wrapping = fyne.TextWrapWord

	// Create form
	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Mount Point:", mountPointEntry),
		},
	}

	// Add browse button next to entry
	mountPointContainer := container.NewBorder(nil, nil, nil, browseBtn, mountPointEntry)
	form.Items[0].Widget = mountPointContainer

	content := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Mount Vault: %s", vaultName)),
		widget.NewSeparator(),
		instructionLabel,
		widget.NewSeparator(),
		form,
	)

	mountDialog := dialog.NewCustomConfirm("Mount Vault", "Mount", "Cancel", content,
		func(confirm bool) {
			if !confirm {
				return
			}

			mountPoint := mountPointEntry.Text
			if mountPoint == "" {
				mw.showError("Validation Error", "Please specify a mount point")
				return
			}

			mw.performMount(mountPoint)
		},
		mw.window,
	)

	mountDialog.Resize(fyne.NewSize(500, 350))
	mountDialog.Show()
}

// showDriveLetterDialog shows Windows drive letter selection
func (mw *MainWindow) showDriveLetterDialog(mountPointEntry *widget.Entry) {
	// Available drive letters (excluding commonly used ones)
	driveLetters := []string{
		"V:", "W:", "X:", "Y:", "Z:", // Preferred letters
		"E:", "F:", "G:", "H:", "I:", "J:", "K:", "L:", "M:",
		"N:", "O:", "P:", "Q:", "R:", "S:", "T:", "U:",
	}

	driveSelect := widget.NewSelect(driveLetters, func(selected string) {
		mountPointEntry.SetText(selected)
	})
	driveSelect.SetSelected("V:") // Default selection

	content := container.NewVBox(
		widget.NewLabel("Select an available drive letter:"),
		driveSelect,
		widget.NewLabel("Note: Make sure the selected drive letter is not already in use."),
	)

	driveDialog := dialog.NewCustomConfirm("Select Drive Letter", "Select", "Cancel", content,
		func(confirm bool) {
			if confirm && driveSelect.Selected != "" {
				mountPointEntry.SetText(driveSelect.Selected)
			}
		},
		mw.window,
	)

	driveDialog.Show()
}

// performMount performs the actual vault mounting operation
func (mw *MainWindow) performMount(mountPoint string) {
	vaultName := filepath.Base(mw.selectedVault)

	// Show progress dialog
	progressBar := widget.NewProgressBarInfinite()
	progressContent := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Mounting '%s' at '%s'...", vaultName, mountPoint)),
		progressBar,
	)
	progress := dialog.NewCustomWithoutButtons("Mounting Vault", progressContent, mw.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		// TODO: Implement vault mounting
		mw.showError("Not Implemented", "Vault mounting is not yet implemented in the GUI")
	}()
}

// performUnmount performs the actual vault unmounting operation
func (mw *MainWindow) performUnmount() {
	vaultName := filepath.Base(mw.selectedVault)

	// Show progress dialog
	progressBar := widget.NewProgressBarInfinite()
	progressContent := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Unmounting '%s'...", vaultName)),
		progressBar,
	)
	progress := dialog.NewCustomWithoutButtons("Unmounting Vault", progressContent, mw.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		// TODO: Implement vault unmounting
		mw.showError("Not Implemented", "Vault unmounting is not yet implemented in the GUI")
	}()
}

// showMountTroubleshooting shows troubleshooting information for mount failures
func (mw *MainWindow) showMountTroubleshooting(err error) {
	var troubleshootingText string

	switch runtime.GOOS {
	case "windows":
		troubleshootingText = `Mount failed on Windows. Common solutions:

1. Install Dokany or WinFSP:
   • Download from: https://github.com/dokan-dev/dokany/releases
   • Or: https://github.com/billziss-gh/winfsp/releases

2. Run as Administrator:
   • Right-click dirLocker and select "Run as administrator"

3. Check drive letter availability:
   • Make sure the selected drive letter is not in use

4. Antivirus software:
   • Some antivirus programs block filesystem drivers
   • Add dirLocker to your antivirus whitelist`

	case "darwin":
		troubleshootingText = `Mount failed on macOS. Common solutions:

1. Install macFUSE:
   • Download from: https://osxfuse.github.io/
   • Follow installation instructions and restart

2. Enable System Extension:
   • Go to System Preferences > Security & Privacy
   • Allow macFUSE system extension if prompted

3. Check mount point permissions:
   • Make sure you have write access to the mount directory
   • Try using /tmp/vault_mount as a test location

4. Gatekeeper issues:
   • You may need to allow dirLocker in Security & Privacy settings`

	default: // Linux
		troubleshootingText = `Mount failed on Linux. Common solutions:

1. Install FUSE:
   • Ubuntu/Debian: sudo apt install fuse
   • CentOS/RHEL: sudo yum install fuse
   • Arch: sudo pacman -S fuse2

2. Add user to fuse group:
   • sudo usermod -a -G fuse $USER
   • Log out and back in

3. Check mount point permissions:
   • Make sure you have write access to the mount directory
   • Try using /tmp/vault_mount as a test location

4. Load fuse module:
   • sudo modprobe fuse`
	}

	dialog.ShowInformation("Mount Troubleshooting", troubleshootingText, mw.window)
}

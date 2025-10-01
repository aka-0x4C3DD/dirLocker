package gui

import (
	"fmt"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"dirLocker/pkg/filehider"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

// FileHidingInterface provides the GUI for file hiding operations
type FileHidingInterface struct {
	vaultManager *vault.VaultManager
	logger       *logging.Logger
	fileHider    filehider.FileHider

	// UI components
	hiddenFilesList *widget.List
	toolbar         *fyne.Container
	statusLabel     *widget.Label

	// Current state
	hiddenFiles        []filehider.HiddenFileInfo
	selectedHiddenFile int

	// Buttons
	hideBtn    *widget.Button
	unhideBtn  *widget.Button
	refreshBtn *widget.Button
}

// NewFileHidingInterface creates a new file hiding interface
func NewFileHidingInterface(vaultManager *vault.VaultManager, logger *logging.Logger) *FileHidingInterface {
	fhi := &FileHidingInterface{
		vaultManager:       vaultManager,
		logger:             logger,
		hiddenFiles:        []filehider.HiddenFileInfo{},
		selectedHiddenFile: -1,
	}

	// Initialize file hider
	var err error
	fhi.fileHider, err = filehider.NewFileHider()
	if err != nil {
		logger.Error("Failed to initialize file hider", "error", err)
	}

	fhi.setupUI()
	fhi.refreshHiddenFiles()

	return fhi
}

// setupUI initializes the file hiding interface UI
func (fhi *FileHidingInterface) setupUI() {
	// Create hidden files list
	fhi.hiddenFilesList = widget.NewList(
		func() int {
			return len(fhi.hiddenFiles)
		},
		func() fyne.CanvasObject {
			return container.NewVBox(
				container.NewHBox(
					widget.NewIcon(resourceHiddenFileIcon),
					widget.NewLabel("File Name"),
				),
				widget.NewLabel("Details"),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(fhi.hiddenFiles) {
				return
			}

			file := fhi.hiddenFiles[id]

			vbox := obj.(*fyne.Container)
			headerContainer := vbox.Objects[0].(*fyne.Container)
			detailsLabel := vbox.Objects[1].(*widget.Label)

			// Update header
			icon := headerContainer.Objects[0].(*widget.Icon)
			nameLabel := headerContainer.Objects[1].(*widget.Label)

			icon.SetResource(resourceHiddenFileIcon)
			nameLabel.SetText(filepath.Base(file.OriginalPath))

			// Update details
			sizeStr := formatFileSize(file.FileSize)
			timeStr := file.HiddenAt.Format("2006-01-02 15:04")
			detailsLabel.SetText(fmt.Sprintf("Size: %s | Hidden: %s", sizeStr, timeStr))
		},
	)

	fhi.hiddenFilesList.OnSelected = func(id widget.ListItemID) {
		fhi.selectedHiddenFile = id
		fhi.updateButtonStates()
	}

	// Create toolbar buttons
	fhi.hideBtn = widget.NewButton("Hide File/Folder", fhi.showHideDialog)
	fhi.unhideBtn = widget.NewButton("Unhide Selected", fhi.unhideSelected)
	fhi.refreshBtn = widget.NewButton("Refresh", fhi.refreshHiddenFiles)

	fhi.toolbar = container.NewHBox(
		fhi.hideBtn,
		fhi.unhideBtn,
		widget.NewSeparator(),
		fhi.refreshBtn,
	)

	// Status label
	fhi.statusLabel = widget.NewLabel("Ready")

	fhi.updateButtonStates()
}

// CreateContent returns the file hiding interface content
func (fhi *FileHidingInterface) CreateContent() fyne.CanvasObject {
	// Instructions text
	instructions := widget.NewRichTextFromMarkdown(`
## File Hiding System

The file hiding system makes files and folders completely invisible to the operating system while keeping them accessible through dirLocker.

**Features:**
- Files become invisible to file browsers and directory listings
- Encrypted metadata registry tracks hidden files
- File integrity verification with checksums
- Cross-platform support (Windows, macOS, Linux)

**Usage:**
1. Click "Hide File/Folder" to select files to hide
2. Hidden files appear in the list below with visual indicators
3. Use "Unhide Selected" to restore files to normal visibility
4. Files remain accessible only through dirLocker while hidden
`)
	instructions.Wrapping = fyne.TextWrapWord

	// Create main layout
	content := container.NewBorder(
		container.NewVBox(
			instructions,
			widget.NewSeparator(),
			fhi.toolbar,
		),
		fhi.statusLabel,
		nil,
		nil,
		container.NewBorder(
			widget.NewLabel("Hidden Files:"),
			nil,
			nil,
			nil,
			fhi.hiddenFilesList,
		),
	)

	return content
}

// refreshHiddenFiles updates the list of hidden files
func (fhi *FileHidingInterface) refreshHiddenFiles() {
	if fhi.fileHider == nil {
		fhi.statusLabel.SetText("File hider not available")
		return
	}

	files, err := fhi.fileHider.ListHidden()
	if err != nil {
		fhi.logger.Error("Failed to list hidden files", "error", err)
		fhi.statusLabel.SetText(fmt.Sprintf("Error: %v", err))
		return
	}

	fhi.hiddenFiles = files
	fhi.hiddenFilesList.Refresh()
	fhi.updateButtonStates()

	count := len(files)
	if count == 0 {
		fhi.statusLabel.SetText("No hidden files")
	} else if count == 1 {
		fhi.statusLabel.SetText("1 file hidden")
	} else {
		fhi.statusLabel.SetText(fmt.Sprintf("%d files hidden", count))
	}

	fhi.logger.Info("Refreshed hidden files list", "count", count)
}

// updateButtonStates enables/disables buttons based on selection
func (fhi *FileHidingInterface) updateButtonStates() {
	hasSelection := fhi.selectedHiddenFile >= 0 && fhi.selectedHiddenFile < len(fhi.hiddenFiles)

	if fhi.fileHider != nil {
		fhi.hideBtn.Enable()
		if hasSelection {
			fhi.unhideBtn.Enable()
		} else {
			fhi.unhideBtn.Disable()
		}
	} else {
		fhi.hideBtn.Disable()
		fhi.unhideBtn.Disable()
	}
}

// showHideDialog displays the hide file/folder dialog
func (fhi *FileHidingInterface) showHideDialog() {
	if fhi.fileHider == nil {
		fhi.showError("File Hiding Error", "File hider is not available")
		return
	}

	// Create selection dialog
	fileBtn := widget.NewButton("Hide File", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			reader.Close()
			fhi.hideFile(reader.URI().Path())
		}, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	folderBtn := widget.NewButton("Hide Folder", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil || uri == nil {
				return
			}
			fhi.hideFile(uri.Path())
		}, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	content := container.NewVBox(
		widget.NewLabel("Select what to hide:"),
		widget.NewSeparator(),
		fileBtn,
		folderBtn,
	)

	selectionDialog := dialog.NewCustom("Hide File or Folder", "Cancel", content, fyne.CurrentApp().Driver().AllWindows()[0])
	selectionDialog.Show()
}

// hideFile hides the specified file or folder
func (fhi *FileHidingInterface) hideFile(path string) {
	if fhi.fileHider == nil {
		fhi.showError("File Hiding Error", "File hider is not available")
		return
	}

	// Check if file is already hidden
	if fhi.fileHider.IsHidden(path) {
		fhi.showError("File Hiding Error", "File is already hidden")
		return
	}

	// Show confirmation dialog
	fileName := filepath.Base(path)
	dialog.ShowConfirm("Hide File",
		fmt.Sprintf("Are you sure you want to hide '%s'?\n\nThe file will become invisible to the operating system but remain accessible through dirLocker.", fileName),
		func(confirm bool) {
			if confirm {
				fhi.performHideFile(path)
			}
		},
		fyne.CurrentApp().Driver().AllWindows()[0],
	)
}

// performHideFile performs the actual file hiding operation
func (fhi *FileHidingInterface) performHideFile(path string) {
	// Show progress dialog
	progress := dialog.NewProgressInfinite("Hiding File", fmt.Sprintf("Hiding '%s'...", filepath.Base(path)), fyne.CurrentApp().Driver().AllWindows()[0])
	progress.Show()

	go func() {
		defer progress.Hide()

		err := fhi.fileHider.HideFile(path)
		if err != nil {
			fhi.showError("File Hiding Error", fmt.Sprintf("Failed to hide file: %v", err))
			return
		}

		fhi.logger.Info("File hidden from GUI", "path", path)
		fhi.refreshHiddenFiles()
		fhi.showInfo("Success", fmt.Sprintf("File '%s' has been hidden", filepath.Base(path)))
	}()
}

// unhideSelected unhides the selected file
func (fhi *FileHidingInterface) unhideSelected() {
	if fhi.fileHider == nil {
		fhi.showError("File Hiding Error", "File hider is not available")
		return
	}

	if fhi.selectedHiddenFile < 0 || fhi.selectedHiddenFile >= len(fhi.hiddenFiles) {
		return
	}

	selectedID := fhi.selectedHiddenFile

	file := fhi.hiddenFiles[selectedID]
	fileName := filepath.Base(file.OriginalPath)

	// Show confirmation dialog
	dialog.ShowConfirm("Unhide File",
		fmt.Sprintf("Are you sure you want to unhide '%s'?\n\nThe file will become visible to the operating system again.", fileName),
		func(confirm bool) {
			if confirm {
				fhi.performUnhideFile(file.OriginalPath)
			}
		},
		fyne.CurrentApp().Driver().AllWindows()[0],
	)
}

// performUnhideFile performs the actual file unhiding operation
func (fhi *FileHidingInterface) performUnhideFile(originalPath string) {
	// Show progress dialog
	progress := dialog.NewProgressInfinite("Unhiding File", fmt.Sprintf("Unhiding '%s'...", filepath.Base(originalPath)), fyne.CurrentApp().Driver().AllWindows()[0])
	progress.Show()

	go func() {
		defer progress.Hide()

		err := fhi.fileHider.UnhideFile(filepath.Base(originalPath))
		if err != nil {
			fhi.showError("File Hiding Error", fmt.Sprintf("Failed to unhide file: %v", err))
			return
		}

		fhi.logger.Info("File unhidden from GUI", "path", originalPath)
		fhi.refreshHiddenFiles()
		fhi.showInfo("Success", fmt.Sprintf("File '%s' has been unhidden", filepath.Base(originalPath)))
	}()
}

// Utility methods

func (fhi *FileHidingInterface) showError(title, message string) {
	dialog.ShowError(fmt.Errorf("%s", message), fyne.CurrentApp().Driver().AllWindows()[0])
}

func (fhi *FileHidingInterface) showInfo(title, message string) {
	dialog.ShowInformation(title, message, fyne.CurrentApp().Driver().AllWindows()[0])
}

// formatFileSize formats a file size in bytes to a human-readable string
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

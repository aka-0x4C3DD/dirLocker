package gui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

// VaultBrowser provides a tree view for browsing vault contents
type VaultBrowser struct {
	vaultManager  *vault.VaultManager
	logger        *logging.Logger
	notifications *NotificationManager

	// UI components
	tree         *widget.Tree
	toolbar      *fyne.Container
	currentVault string

	// File operations
	extractBtn    *widget.Button
	addFileBtn    *widget.Button
	addFolderBtn  *widget.Button
	deleteBtn     *widget.Button
	propertiesBtn *widget.Button

	// Selection tracking
	selectedUID string

	// File data cache
	fileCache []vault.FileEntry
}

// FileNode represents a file or directory in the vault
type FileNode struct {
	Name     string
	Path     string
	IsDir    bool
	Size     int64
	Children []*FileNode
}

// NewVaultBrowser creates a new vault browser
func NewVaultBrowser(vaultManager *vault.VaultManager, logger *logging.Logger, notifications *NotificationManager) *VaultBrowser {
	vb := &VaultBrowser{
		vaultManager:  vaultManager,
		logger:        logger,
		notifications: notifications,
		fileCache:     []vault.FileEntry{},
	}

	vb.setupUI()
	return vb
}

// setupUI initializes the vault browser UI
func (vb *VaultBrowser) setupUI() {
	// Create tree widget
	vb.tree = widget.NewTree(
		func(uid widget.TreeNodeID) []widget.TreeNodeID {
			return vb.getChildUIDs(uid)
		},
		func(uid widget.TreeNodeID) bool {
			return vb.isDirectory(uid)
		},
		func(branch bool) fyne.CanvasObject {
			icon := widget.NewIcon(nil)
			label := widget.NewLabel("Node")
			return container.NewHBox(icon, label)
		},
		func(uid widget.TreeNodeID, branch bool, obj fyne.CanvasObject) {
			vb.updateTreeNode(uid, branch, obj)
		},
	)

	// Create toolbar buttons
	vb.extractBtn = widget.NewButton("Extract", vb.extractSelected)
	vb.addFileBtn = widget.NewButton("Add File", vb.addFile)
	vb.addFolderBtn = widget.NewButton("Add Folder", vb.addFolder)
	vb.deleteBtn = widget.NewButton("Delete", vb.deleteSelected)
	vb.propertiesBtn = widget.NewButton("Properties", vb.showProperties)

	// Initially disable buttons
	vb.setButtonsEnabled(false)

	vb.toolbar = container.NewHBox(
		vb.addFileBtn,
		vb.addFolderBtn,
		widget.NewSeparator(),
		vb.extractBtn,
		vb.deleteBtn,
		widget.NewSeparator(),
		vb.propertiesBtn,
	)

	// Set up tree selection handler
	vb.tree.OnSelected = func(uid widget.TreeNodeID) {
		vb.selectedUID = string(uid)
		vb.setButtonsEnabled(uid != "")
		if uid != "" {
			vb.logger.Info("Selected vault item", "path", uid)
		}
	}
}

// CreateContent returns the vault browser content
func (vb *VaultBrowser) CreateContent() fyne.CanvasObject {
	return container.NewBorder(
		vb.toolbar, // top
		nil,        // bottom
		nil,        // left
		nil,        // right
		vb.tree,    // center
	)
}

// SetVault sets the current vault to browse
func (vb *VaultBrowser) SetVault(vaultPath string) {
	vb.currentVault = vaultPath
	vb.refreshTree()
	vb.setButtonsEnabled(false)
}

// refreshTree refreshes the tree view with current vault contents
func (vb *VaultBrowser) refreshTree() {
	if vb.currentVault == "" {
		vb.fileCache = []vault.FileEntry{}
		vb.tree.Refresh()
		return
	}

	// Get vault contents
	managedVault, exists := vb.vaultManager.GetVault(vb.currentVault)
	if !exists {
		vb.logger.Error("Vault not found for browsing", "vault", vb.currentVault)
		vb.notifications.SendError("Vault Error", "Vault not found for browsing")
		return
	}

	// List files from vault
	files, err := managedVault.ListFiles()
	if err != nil {
		vb.logger.Error("Failed to list vault files", "error", err, "vault", vb.currentVault)
		vb.notifications.SendError("Vault Error", fmt.Sprintf("Failed to list files: %v", err))
		vb.fileCache = []vault.FileEntry{}
	} else {
		vb.fileCache = files
		vb.logger.Info("Refreshed vault browser", "vault", vb.currentVault, "files", len(files))
	}

	vb.tree.Refresh()
}

// getChildUIDs returns child node IDs for the tree
func (vb *VaultBrowser) getChildUIDs(uid widget.TreeNodeID) []widget.TreeNodeID {
	if vb.currentVault == "" {
		return []widget.TreeNodeID{}
	}

	var children []widget.TreeNodeID

	if uid == "" {
		// Root level - return top-level files and directories
		for _, file := range vb.fileCache {
			if !strings.Contains(file.Name, "/") {
				children = append(children, widget.TreeNodeID(file.Name))
			}
		}
	} else {
		// Return children of the specified directory
		prefix := string(uid) + "/"
		for _, file := range vb.fileCache {
			if strings.HasPrefix(file.Name, prefix) {
				relativePath := strings.TrimPrefix(file.Name, prefix)
				if !strings.Contains(relativePath, "/") {
					children = append(children, widget.TreeNodeID(file.Name))
				}
			}
		}
	}

	return children
}

// isDirectory checks if a node is a directory
func (vb *VaultBrowser) isDirectory(uid widget.TreeNodeID) bool {
	if vb.currentVault == "" {
		return false
	}

	for _, file := range vb.fileCache {
		if file.Name == string(uid) {
			return file.IsDir
		}
	}

	return false
}

// updateTreeNode updates the display of a tree node
func (vb *VaultBrowser) updateTreeNode(uid widget.TreeNodeID, branch bool, obj fyne.CanvasObject) {
	hbox := obj.(*fyne.Container)
	icon := hbox.Objects[0].(*widget.Icon)
	label := hbox.Objects[1].(*widget.Label)

	nodeName := filepath.Base(string(uid))
	if nodeName == "" || nodeName == "." {
		nodeName = string(uid)
	}

	label.SetText(nodeName)

	// Set appropriate icon
	if branch {
		icon.SetResource(resourceFolderIcon)
	} else {
		icon.SetResource(resourceFileIcon)
	}
}

// setButtonsEnabled enables or disables toolbar buttons
func (vb *VaultBrowser) setButtonsEnabled(enabled bool) {
	if enabled && vb.currentVault != "" {
		vb.extractBtn.Enable()
		vb.deleteBtn.Enable()
		vb.propertiesBtn.Enable()
	} else {
		vb.extractBtn.Disable()
		vb.deleteBtn.Disable()
		vb.propertiesBtn.Disable()
	}

	// Add buttons are enabled when vault is open
	if vb.currentVault != "" {
		vb.addFileBtn.Enable()
		vb.addFolderBtn.Enable()
	} else {
		vb.addFileBtn.Disable()
		vb.addFolderBtn.Disable()
	}
}

// File operation handlers

func (vb *VaultBrowser) addFile() {
	if vb.currentVault == "" {
		return
	}

	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		defer reader.Close()

		// Get destination path in vault
		fileName := reader.URI().Name()

		// Show path input dialog
		pathEntry := widget.NewEntry()
		pathEntry.SetText(fileName)

		pathDialog := dialog.NewForm("Add File to Vault", "Add", "Cancel",
			[]*widget.FormItem{
				widget.NewFormItem("Vault Path:", pathEntry),
			},
			func(confirm bool) {
				if !confirm {
					return
				}

				vaultPath := pathEntry.Text
				if vaultPath == "" {
					return
				}

				vb.addFileToVault(reader.URI(), vaultPath)
			},
			fyne.CurrentApp().Driver().AllWindows()[0],
		)

		pathDialog.Show()
	}, fyne.CurrentApp().Driver().AllWindows()[0])
}

func (vb *VaultBrowser) addFolder() {
	if vb.currentVault == "" {
		return
	}

	// Show folder name input dialog
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Folder name")

	folderDialog := dialog.NewForm("Create Folder", "Create", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Folder Name:", nameEntry),
		},
		func(confirm bool) {
			if !confirm {
				return
			}

			folderName := nameEntry.Text
			if folderName == "" {
				return
			}

			vb.createFolderInVault(folderName)
		},
		fyne.CurrentApp().Driver().AllWindows()[0],
	)

	folderDialog.Show()
}

func (vb *VaultBrowser) extractSelected() {
	if vb.selectedUID == "" || vb.currentVault == "" {
		return
	}
	selected := vb.selectedUID

	dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
		if err != nil || uri == nil {
			return
		}

		vb.extractFromVault(string(selected), uri.Path())
	}, fyne.CurrentApp().Driver().AllWindows()[0])
}

func (vb *VaultBrowser) deleteSelected() {
	if vb.selectedUID == "" || vb.currentVault == "" {
		return
	}
	selected := vb.selectedUID

	dialog.ShowConfirm("Delete File",
		fmt.Sprintf("Are you sure you want to delete '%s'?", filepath.Base(string(selected))),
		func(confirm bool) {
			if confirm {
				vb.deleteFromVault(string(selected))
			}
		},
		fyne.CurrentApp().Driver().AllWindows()[0],
	)
}

// Vault operation implementations

func (vb *VaultBrowser) addFileToVault(sourceURI fyne.URI, vaultPath string) {
	managedVault, exists := vb.vaultManager.GetVault(vb.currentVault)
	if !exists {
		vb.showError("Add File Error", "Vault not found")
		return
	}

	// Show progress notification
	progress := NewProgressNotification("Adding File", fmt.Sprintf("Adding %s to vault...", filepath.Base(vaultPath)))
	progress.Show()

	go func() {
		defer progress.Hide()

		// Read source file
		reader, err := storage.Reader(sourceURI)
		if err != nil {
			vb.showError("Add File Error", fmt.Sprintf("Failed to read source file: %v", err))
			vb.notifications.SendError("Add File Failed", fmt.Sprintf("Could not read %s", sourceURI.Name()))
			return
		}
		defer reader.Close()

		// Read file data
		data := make([]byte, 0)
		buffer := make([]byte, 4096)
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				data = append(data, buffer[:n]...)
			}
			if err != nil {
				break
			}
		}

		progress.UpdateProgress(0.5, "Writing to vault...")

		// Add file to vault
		err = managedVault.AddFile(vaultPath, data)
		if err != nil {
			vb.showError("Add File Error", fmt.Sprintf("Failed to add file to vault: %v", err))
			vb.notifications.SendError("Add File Failed", fmt.Sprintf("Could not add %s to vault", filepath.Base(vaultPath)))
			return
		}

		progress.UpdateProgress(1.0, "Complete")

		// Refresh tree and notify success
		vb.refreshTree()
		vb.notifications.SendSuccess("File Added", fmt.Sprintf("Successfully added %s to vault", filepath.Base(vaultPath)))
		vb.logger.Info("File added to vault", "source", sourceURI.Path(), "vault_path", vaultPath)
	}()
}

func (vb *VaultBrowser) createFolderInVault(folderName string) {
	managedVault, exists := vb.vaultManager.GetVault(vb.currentVault)
	if !exists {
		vb.showError("Create Folder Error", "Vault not found")
		return
	}

	// Determine full path based on current selection
	var fullPath string
	if vb.selectedUID != "" && vb.isDirectory(widget.TreeNodeID(vb.selectedUID)) {
		fullPath = vb.selectedUID + "/" + folderName
	} else {
		fullPath = folderName
	}

	// Create directory in vault
	err := managedVault.CreateDirectory(fullPath)
	if err != nil {
		vb.showError("Create Folder Error", fmt.Sprintf("Failed to create folder: %v", err))
		vb.notifications.SendError("Create Folder Failed", fmt.Sprintf("Could not create folder %s", folderName))
		return
	}

	// Refresh tree and notify success
	vb.refreshTree()
	vb.notifications.SendSuccess("Folder Created", fmt.Sprintf("Successfully created folder %s", folderName))
	vb.logger.Info("Folder created in vault", "folder", fullPath)
}

func (vb *VaultBrowser) extractFromVault(vaultPath, destDir string) {
	managedVault, exists := vb.vaultManager.GetVault(vb.currentVault)
	if !exists {
		vb.showError("Extract Error", "Vault not found")
		return
	}

	// Show progress notification
	fileName := filepath.Base(vaultPath)
	progress := NewProgressNotification("Extracting File", fmt.Sprintf("Extracting %s from vault...", fileName))
	progress.Show()

	go func() {
		defer progress.Hide()

		progress.UpdateProgress(0.3, "Reading from vault...")

		// Extract file from vault
		data, err := managedVault.ExtractFile(vaultPath)
		if err != nil {
			vb.showError("Extract Error", fmt.Sprintf("Failed to extract file: %v", err))
			vb.notifications.SendError("Extract Failed", fmt.Sprintf("Could not extract %s", fileName))
			return
		}

		progress.UpdateProgress(0.7, "Writing to disk...")

		// Write to destination
		destPath := filepath.Join(destDir, fileName)
		err = os.WriteFile(destPath, data, 0644)
		if err != nil {
			vb.showError("Extract Error", fmt.Sprintf("Failed to write extracted file: %v", err))
			vb.notifications.SendError("Extract Failed", fmt.Sprintf("Could not write %s to disk", fileName))
			return
		}

		progress.UpdateProgress(1.0, "Complete")

		// Notify success
		vb.notifications.SendSuccess("File Extracted", fmt.Sprintf("Successfully extracted %s to %s", fileName, destDir))
		vb.logger.Info("File extracted from vault", "vault_path", vaultPath, "dest_path", destPath)
	}()
}

func (vb *VaultBrowser) deleteFromVault(vaultPath string) {
	managedVault, exists := vb.vaultManager.GetVault(vb.currentVault)
	if !exists {
		vb.showError("Delete Error", "Vault not found")
		return
	}

	fileName := filepath.Base(vaultPath)

	// Delete file from vault
	err := managedVault.DeleteFile(vaultPath)
	if err != nil {
		vb.showError("Delete Error", fmt.Sprintf("Failed to delete file: %v", err))
		vb.notifications.SendError("Delete Failed", fmt.Sprintf("Could not delete %s", fileName))
		return
	}

	// Refresh tree and notify success
	vb.refreshTree()
	vb.selectedUID = "" // Clear selection
	vb.setButtonsEnabled(false)
	vb.notifications.SendSuccess("File Deleted", fmt.Sprintf("Successfully deleted %s", fileName))
	vb.logger.Info("File deleted from vault", "vault_path", vaultPath)
}

// Utility methods

func (vb *VaultBrowser) showError(title, message string) {
	dialog.ShowError(fmt.Errorf("%s", message), fyne.CurrentApp().Driver().AllWindows()[0])
}

func (vb *VaultBrowser) showInfo(title, message string) {
	dialog.ShowInformation(title, message, fyne.CurrentApp().Driver().AllWindows()[0])
}

// showProperties shows the properties dialog for the selected file
func (vb *VaultBrowser) showProperties() {
	if vb.selectedUID == "" || vb.currentVault == "" {
		return
	}

	// Find the file entry
	var fileEntry *vault.FileEntry
	for _, file := range vb.fileCache {
		if file.Name == vb.selectedUID {
			fileEntry = &file
			break
		}
	}

	if fileEntry == nil {
		vb.showError("Properties Error", "File not found")
		return
	}

	// Create properties dialog
	nameLabel := widget.NewLabel(fileEntry.Name)
	typeLabel := widget.NewLabel(func() string {
		if fileEntry.IsDir {
			return "Directory"
		}
		return "File"
	}())

	sizeLabel := widget.NewLabel(func() string {
		if fileEntry.IsDir {
			return "-"
		}
		return fmt.Sprintf("%d bytes", fileEntry.Size)
	}())

	modTimeLabel := widget.NewLabel(func() string {
		if fileEntry.MTime == 0 {
			return "Unknown"
		}
		return fmt.Sprintf("%v", fileEntry.MTime)
	}())

	modeLabel := widget.NewLabel(fmt.Sprintf("0%o", fileEntry.Mode))

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Name:", nameLabel),
			widget.NewFormItem("Type:", typeLabel),
			widget.NewFormItem("Size:", sizeLabel),
			widget.NewFormItem("Modified:", modTimeLabel),
			widget.NewFormItem("Mode:", modeLabel),
		},
	}

	dialog.NewCustom("File Properties", "Close", form, fyne.CurrentApp().Driver().AllWindows()[0]).Show()
}

// setupDragAndDrop sets up drag and drop functionality for the vault browser
func (vb *VaultBrowser) setupDragAndDrop() {
	// TODO: Implement drag and drop support
	// This would require extending Fyne's drag and drop capabilities
	// For now, we'll rely on the "Add File" button
	vb.logger.Debug("Drag and drop support not yet implemented")
}

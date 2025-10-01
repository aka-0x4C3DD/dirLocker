package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Application icons and resources
var (
	// Vault icons
	resourceVaultIcon       = theme.StorageIcon()
	resourceSharedVaultIcon = theme.AccountIcon()

	// File icons
	resourceFileIcon       = theme.DocumentIcon()
	resourceFolderIcon     = theme.FolderIcon()
	resourceHiddenFileIcon = theme.VisibilityOffIcon()

	// Action icons
	resourceCreateIcon   = theme.ContentAddIcon()
	resourceOpenIcon     = theme.FolderOpenIcon()
	resourceCloseIcon    = theme.CancelIcon()
	resourceMountIcon    = theme.ComputerIcon()
	resourceUnmountIcon  = theme.MediaStopIcon()
	resourceSettingsIcon = theme.SettingsIcon()
	resourceRefreshIcon  = theme.ViewRefreshIcon()
	resourceDeleteIcon   = theme.DeleteIcon()
	resourceExtractIcon  = theme.DownloadIcon()
	resourceHideIcon     = theme.VisibilityOffIcon()
	resourceUnhideIcon   = theme.VisibilityIcon()
)

// GetAppIcon returns the main application icon
func GetAppIcon() fyne.Resource {
	return theme.StorageIcon()
}

// GetVaultIcon returns the appropriate icon for a vault based on its properties
func GetVaultIcon(isShared bool, isMounted bool) fyne.Resource {
	if isMounted {
		return theme.ComputerIcon()
	}
	if isShared {
		return resourceSharedVaultIcon
	}
	return resourceVaultIcon
}

// GetFileIcon returns the appropriate icon for a file or directory
func GetFileIcon(isDir bool, isHidden bool) fyne.Resource {
	if isHidden {
		return resourceHiddenFileIcon
	}
	if isDir {
		return resourceFolderIcon
	}
	return resourceFileIcon
}

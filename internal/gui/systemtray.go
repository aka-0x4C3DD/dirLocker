package gui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

// SystemTray manages the system tray integration
type SystemTray struct {
	app           fyne.App
	mainWindow    *MainWindow
	vaultManager  *vault.VaultManager
	logger        *logging.Logger
	notifications *NotificationManager

	// System tray menu
	menu *fyne.Menu

	// Status tracking
	vaultStatus map[string]VaultStatus
}

// VaultStatus represents the status of a vault
type VaultStatus int

const (
	VaultStatusClosed VaultStatus = iota
	VaultStatusOpen
	VaultStatusMounted
	VaultStatusError
)

// NewSystemTray creates a new system tray integration
func NewSystemTray(app fyne.App, mainWindow *MainWindow, vaultManager *vault.VaultManager, logger *logging.Logger) *SystemTray {
	// Create a new notification manager for the system tray
	notifications := NewNotificationManager(app, logger)

	st := &SystemTray{
		app:           app,
		mainWindow:    mainWindow,
		vaultManager:  vaultManager,
		logger:        logger,
		notifications: notifications,
		vaultStatus:   make(map[string]VaultStatus),
	}

	st.setupSystemTray()
	return st
}

// setupSystemTray initializes the system tray
func (st *SystemTray) setupSystemTray() {
	// Check if the app supports system tray
	if desk, ok := st.app.(desktop.App); ok {
		st.menu = fyne.NewMenu("dirLocker",
			fyne.NewMenuItem("Show Window", func() {
				st.showMainWindow()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Create Vault...", func() {
				st.showMainWindow()
				st.mainWindow.showCreateVaultDialog()
			}),
			fyne.NewMenuItem("Open Vault...", func() {
				st.showMainWindow()
				st.mainWindow.showOpenVaultDialog()
			}),
			fyne.NewMenuItemSeparator(),
		)

		// Add dynamic vault menu items
		st.updateVaultMenu()

		// Add static menu items
		st.menu.Items = append(st.menu.Items,
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Settings...", func() {
				st.showMainWindow()
				st.mainWindow.showSettingsDialog()
			}),
			fyne.NewMenuItem("About...", func() {
				st.showMainWindow()
				st.mainWindow.showAboutDialog()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Exit", func() {
				st.app.Quit()
			}),
		)

		desk.SetSystemTrayMenu(st.menu)
		st.logger.Info("System tray initialized")
	} else {
		st.logger.Warn("System tray not supported on this platform")
	}
}

// updateVaultMenu updates the vault-specific menu items
func (st *SystemTray) updateVaultMenu() {
	if st.menu == nil {
		return
	}

	// Remove existing vault menu items (items between separators)
	var newItems []*fyne.MenuItem
	separatorCount := 0

	for _, item := range st.menu.Items {
		if item.IsSeparator {
			separatorCount++
		}

		// Keep items before the second separator and after the vault section
		if separatorCount < 2 || separatorCount >= 4 {
			newItems = append(newItems, item)
		}
	}

	// Insert vault menu items after the second separator
	insertIndex := -1
	separatorCount = 0
	for i, item := range newItems {
		if item.IsSeparator {
			separatorCount++
			if separatorCount == 2 {
				insertIndex = i + 1
				break
			}
		}
	}

	if insertIndex >= 0 {
		vaultItems := st.createVaultMenuItems()

		// Insert vault items
		result := make([]*fyne.MenuItem, 0, len(newItems)+len(vaultItems))
		result = append(result, newItems[:insertIndex]...)
		result = append(result, vaultItems...)
		result = append(result, newItems[insertIndex:]...)

		st.menu.Items = result
	}

	// Update system tray
	if desk, ok := st.app.(desktop.App); ok {
		desk.SetSystemTrayMenu(st.menu)
	}
}

// createVaultMenuItems creates menu items for open vaults
func (st *SystemTray) createVaultMenuItems() []*fyne.MenuItem {
	openVaults := st.vaultManager.ListOpenVaults()

	if len(openVaults) == 0 {
		menuItem := fyne.NewMenuItem("No vaults open", nil)
		menuItem.Disabled = true
		return []*fyne.MenuItem{menuItem}
	}

	var items []*fyne.MenuItem

	for _, vaultPath := range openVaults {
		vaultPath := vaultPath // Capture for closure
		vaultName := getVaultDisplayName(vaultPath)

		// Create submenu for each vault
		vaultSubmenu := fyne.NewMenu(vaultName,
			fyne.NewMenuItem("Show Contents", func() {
				st.showMainWindow()
				st.mainWindow.selectedVault = vaultPath
				st.mainWindow.updateVaultBrowser()
			}),
			fyne.NewMenuItem("Mount...", func() {
				st.showMainWindow()
				st.mainWindow.selectedVault = vaultPath
				st.mainWindow.mountSelectedVault()
			}),
			fyne.NewMenuItem("Unmount", func() {
				st.showMainWindow()
				st.mainWindow.selectedVault = vaultPath
				st.mainWindow.unmountSelectedVault()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Close Vault", func() {
				st.closeVaultFromTray(vaultPath)
			}),
		)

		// TODO: Check if vault is mounted and update menu accordingly
		// For now, assume all vaults are unmounted
		vaultSubmenu.Items[1].Disabled = false // Mount option
		vaultSubmenu.Items[2].Disabled = true  // Unmount option

		menuItem := fyne.NewMenuItem(vaultName, nil)
		menuItem.ChildMenu = vaultSubmenu
		items = append(items, menuItem)
	}

	return items
}

// showMainWindow shows and focuses the main window
func (st *SystemTray) showMainWindow() {
	st.mainWindow.window.Show()
	st.mainWindow.window.RequestFocus()

	// Bring to front
	st.mainWindow.window.RequestFocus()
}

// closeVaultFromTray closes a vault from the system tray
func (st *SystemTray) closeVaultFromTray(vaultPath string) {
	err := st.vaultManager.CloseVault(vaultPath)
	if err != nil {
		st.logger.Error("Failed to close vault from tray", "vault", vaultPath, "error", err)

		// TODO: Show notification about the error
		// Notifications not implemented yet
		return
	}

	st.logger.Info("Vault closed from system tray", "vault", vaultPath)

	// Update the tray menu
	st.updateVaultMenu()

	// TODO: Show success notification
	// Notifications not implemented yet
}

// SendNotification sends a system notification
func (st *SystemTray) SendNotification(title, content string) {
	st.notifications.SendInfo(title, content)
}

// UpdateVaultStatus updates the status of a vault
func (st *SystemTray) UpdateVaultStatus(vaultPath string, status VaultStatus) {
	st.vaultStatus[vaultPath] = status
	st.updateVaultMenu()

	// Send status notification
	vaultName := getVaultDisplayName(vaultPath)
	switch status {
	case VaultStatusOpen:
		st.notifications.SendSuccess("Vault Opened", fmt.Sprintf("%s is now open", vaultName))
	case VaultStatusClosed:
		st.notifications.SendInfo("Vault Closed", fmt.Sprintf("%s has been closed", vaultName))
	case VaultStatusMounted:
		st.notifications.SendSuccess("Vault Mounted", fmt.Sprintf("%s is now mounted", vaultName))
	case VaultStatusError:
		st.notifications.SendError("Vault Error", fmt.Sprintf("Error with vault %s", vaultName))
	}
}

// UpdateMenu updates the system tray menu (called when vaults change)
func (st *SystemTray) UpdateMenu() {
	st.updateVaultMenu()
}

// getVaultDisplayName returns a display-friendly name for a vault
func getVaultDisplayName(vaultPath string) string {
	// Extract filename without extension
	name := vaultPath
	if len(name) > 50 {
		// Truncate long paths
		name = "..." + name[len(name)-47:]
	}
	return name
}

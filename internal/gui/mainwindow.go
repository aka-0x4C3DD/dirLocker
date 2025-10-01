package gui

import (
	"fmt"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

// MainWindow represents the main application window
type MainWindow struct {
	app          fyne.App
	window       fyne.Window
	vaultManager *vault.VaultManager
	config       *config.Config
	logger       *logging.Logger

	// UI components
	vaultList     *widget.List
	vaultBrowser  *VaultBrowser
	fileHiding    *FileHidingInterface
	statusBar     *widget.Label
	notifications *NotificationManager

	// Current state
	openVaults    []string
	selectedVault string
}

// NewMainWindow creates a new main window
func NewMainWindow(app fyne.App, vaultManager *vault.VaultManager, cfg *config.Config, logger *logging.Logger) *MainWindow {
	window := app.NewWindow("dirLocker - Encrypted Vault Manager")
	window.SetMaster()
	window.Resize(fyne.NewSize(1000, 700))

	notifications := NewNotificationManager(app, logger)

	mw := &MainWindow{
		app:           app,
		window:        window,
		vaultManager:  vaultManager,
		config:        cfg,
		logger:        logger,
		openVaults:    []string{},
		statusBar:     widget.NewLabel("Ready"),
		notifications: notifications,
	}

	mw.setupUI()
	mw.setupMenus()
	mw.updateVaultList()

	return mw
}

// setupUI initializes the user interface layout
func (mw *MainWindow) setupUI() {
	// Create vault list
	mw.vaultList = widget.NewList(
		func() int {
			return len(mw.openVaults)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(nil),
				widget.NewLabel("Vault Name"),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(mw.openVaults) {
				return
			}

			vaultPath := mw.openVaults[id]
			vaultName := filepath.Base(vaultPath)

			hbox := obj.(*fyne.Container)
			icon := hbox.Objects[0].(*widget.Icon)
			label := hbox.Objects[1].(*widget.Label)

			// Set vault icon based on type
			managedVault, exists := mw.vaultManager.GetVault(vaultPath)
			if exists && managedVault != nil {
				_, _, _, isShared := managedVault.GetInfo()
				if isShared {
					icon.SetResource(resourceSharedVaultIcon)
				} else {
					icon.SetResource(resourceVaultIcon)
				}
			} else {
				icon.SetResource(resourceVaultIcon)
			}

			label.SetText(vaultName)
		},
	)

	mw.vaultList.OnSelected = func(id widget.ListItemID) {
		if id >= len(mw.openVaults) {
			return
		}
		mw.selectedVault = mw.openVaults[id]
		mw.updateVaultBrowser()
		mw.logger.Info("Selected vault", "path", mw.selectedVault)
	}

	// Create vault browser with notification manager
	mw.vaultBrowser = NewVaultBrowser(mw.vaultManager, mw.logger, mw.notifications)

	// Create file hiding interface
	mw.fileHiding = NewFileHidingInterface(mw.vaultManager, mw.logger)

	// Create main layout with tabs
	tabs := container.NewAppTabs(
		container.NewTabItem("Vaults", mw.createVaultTab()),
		container.NewTabItem("File Hiding", mw.fileHiding.CreateContent()),
	)

	// Main content with status bar
	content := container.NewBorder(
		nil,          // top
		mw.statusBar, // bottom
		nil,          // left
		nil,          // right
		tabs,         // center
	)

	mw.window.SetContent(content)
}

// createVaultTab creates the vault management tab
func (mw *MainWindow) createVaultTab() fyne.CanvasObject {
	// Left panel with vault list and controls
	vaultControls := container.NewVBox(
		widget.NewButton("Create Vault", mw.showCreateVaultDialog),
		widget.NewButton("Open Vault", mw.showOpenVaultDialog),
		widget.NewButton("Close Vault", mw.closeSelectedVault),
		widget.NewSeparator(),
		widget.NewButton("Mount Vault", mw.mountSelectedVault),
		widget.NewButton("Unmount Vault", mw.unmountSelectedVault),
	)

	leftPanel := container.NewBorder(
		widget.NewLabel("Open Vaults:"),
		vaultControls,
		nil,
		nil,
		mw.vaultList,
	)

	// Right panel with vault browser
	rightPanel := container.NewBorder(
		widget.NewLabel("Vault Contents:"),
		nil,
		nil,
		nil,
		mw.vaultBrowser.CreateContent(),
	)

	// Split layout
	split := container.NewHSplit(leftPanel, rightPanel)
	split.SetOffset(0.3) // 30% for vault list, 70% for browser

	return split
}

// setupMenus creates the application menus
func (mw *MainWindow) setupMenus() {
	// File menu
	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Create Vault...", mw.showCreateVaultDialog),
		fyne.NewMenuItem("Open Vault...", mw.showOpenVaultDialog),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Close Vault", mw.closeSelectedVault),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Exit", func() {
			mw.app.Quit()
		}),
	)

	// Tools menu
	toolsMenu := fyne.NewMenu("Tools",
		fyne.NewMenuItem("Mount Vault", mw.mountSelectedVault),
		fyne.NewMenuItem("Unmount Vault", mw.unmountSelectedVault),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Generate Recovery Key...", mw.showGenerateRecoveryKeyDialog),
		fyne.NewMenuItem("Import Recovery Key...", mw.showImportRecoveryKeyDialog),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Settings...", mw.showSettingsDialog),
	)

	// Help menu
	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("About...", mw.showAboutDialog),
	)

	mainMenu := fyne.NewMainMenu(fileMenu, toolsMenu, helpMenu)
	mw.window.SetMainMenu(mainMenu)
}

// updateVaultList refreshes the vault list display
func (mw *MainWindow) updateVaultList() {
	mw.openVaults = mw.vaultManager.ListOpenVaults()
	mw.vaultList.Refresh()

	// Update status bar
	count := len(mw.openVaults)
	if count == 0 {
		mw.statusBar.SetText("No vaults open")
	} else if count == 1 {
		mw.statusBar.SetText("1 vault open")
	} else {
		mw.statusBar.SetText(fmt.Sprintf("%d vaults open", count))
	}
}

// updateVaultBrowser updates the vault browser content
func (mw *MainWindow) updateVaultBrowser() {
	if mw.selectedVault != "" {
		mw.vaultBrowser.SetVault(mw.selectedVault)
	}
}

// closeSelectedVault closes the currently selected vault
func (mw *MainWindow) closeSelectedVault() {
	if mw.selectedVault == "" {
		return
	}

	err := mw.vaultManager.CloseVault(mw.selectedVault)
	if err != nil {
		mw.showError("Close Vault Error", fmt.Sprintf("Failed to close vault: %v", err))
		return
	}

	mw.logger.Info("Vault closed from GUI", "path", mw.selectedVault)
	mw.selectedVault = ""
	mw.updateVaultList()
	mw.vaultBrowser.SetVault("")
	mw.showInfo("Success", "Vault closed successfully")
}

// Show shows the main window
func (mw *MainWindow) Show() {
	mw.window.Show()
}

// SetOnClosed sets the callback for when the window is closed
func (mw *MainWindow) SetOnClosed(callback func()) {
	mw.window.SetOnClosed(callback)
}

// GetNotificationManager returns the notification manager
func (mw *MainWindow) GetNotificationManager() *NotificationManager {
	return mw.notifications
}

// Note: mountSelectedVault and unmountSelectedVault are implemented in mount.go

// Note: showGenerateRecoveryKeyDialog and showImportRecoveryKeyDialog are implemented in dialogs.go

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Initialize Qt application
	app := widgets.NewQApplication(len(os.Args), os.Args)
	app.SetApplicationName("dirLocker")
	app.SetApplicationVersion(version)
	app.SetOrganizationName("dirLocker")

	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		showErrorDialog(nil, "Configuration Error", fmt.Sprintf("Failed to load config: %v", err))
		os.Exit(1)
	}

	// Initialize logger
	logConfig := &logging.LogConfig{
		Level:   cfg.LogLevel,
		File:    cfg.GetLogPath(),
		Console: false, // GUI mode - no console output
	}
	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		showErrorDialog(nil, "Logging Error", fmt.Sprintf("Failed to initialize logger: %v", err))
		os.Exit(1)
	}
	defer logger.Close()

	// Initialize vault manager
	vaultManager := vault.NewVaultManager(cfg, logger)
	defer vaultManager.CloseAllVaults()

	// Start auto-close timer
	vaultManager.StartAutoCloseTimer()

	// Set application icon if configured
	if cfg.IconPath != "" && fileExists(cfg.IconPath) {
		icon := gui.NewQIcon5(cfg.IconPath)
		app.SetWindowIcon(icon)
	}

	// Create main window
	mainWindow := NewMainWindow(vaultManager, cfg, logger)
	mainWindow.Show()

	// Setup system tray if supported
	if widgets.QSystemTrayIcon_IsSystemTrayAvailable() {
		trayIcon := NewSystemTrayIcon(mainWindow, vaultManager, logger)
		trayIcon.Show()
	}

	logger.Info("GUI application started", "version", version)

	// Run application
	app.Exec()
}

// MainWindow represents the main application window
type MainWindow struct {
	*widgets.QMainWindow

	vaultManager *vault.VaultManager
	config       *config.Config
	logger       *logging.Logger

	// UI components
	centralWidget   *widgets.QWidget
	vaultList       *widgets.QListWidget
	statusBar       *widgets.QStatusBar
	menuBar         *widgets.QMenuBar
	toolbar         *widgets.QToolBar
	
	// Actions
	createAction    *widgets.QAction
	openAction      *widgets.QAction
	closeAction     *widgets.QAction
	settingsAction  *widgets.QAction
	aboutAction     *widgets.QAction
	exitAction      *widgets.QAction
}

// NewMainWindow creates a new main window
func NewMainWindow(vaultManager *vault.VaultManager, cfg *config.Config, logger *logging.Logger) *MainWindow {
	window := &MainWindow{
		QMainWindow:  widgets.NewQMainWindow(nil, 0),
		vaultManager: vaultManager,
		config:       cfg,
		logger:       logger,
	}

	window.setupUI()
	window.connectSignals()
	window.updateVaultList()

	return window
}

// setupUI initializes the user interface
func (w *MainWindow) setupUI() {
	w.SetWindowTitle("dirLocker - Encrypted Vault Manager")
	w.SetMinimumSize2(800, 600)

	// Create central widget
	w.centralWidget = widgets.NewQWidget(nil, 0)
	w.SetCentralWidget(w.centralWidget)

	// Create layout
	layout := widgets.NewQVBoxLayout()
	w.centralWidget.SetLayout(layout)

	// Create vault list
	w.vaultList = widgets.NewQListWidget(nil)
	w.vaultList.SetAlternatingRowColors(true)
	layout.AddWidget(w.vaultList, 0, 0)

	// Create status bar
	w.statusBar = widgets.NewQStatusBar(nil)
	w.SetStatusBar(w.statusBar)
	w.statusBar.ShowMessage("Ready", 0)

	// Setup menu bar
	w.setupMenuBar()

	// Setup toolbar
	w.setupToolBar()
}

// setupMenuBar creates the menu bar
func (w *MainWindow) setupMenuBar() {
	w.menuBar = w.MenuBar()

	// File menu
	fileMenu := w.menuBar.AddMenu2("&File")

	w.createAction = fileMenu.AddAction("&Create Vault...")
	w.createAction.SetShortcut(gui.NewQKeySequence2("Ctrl+N", gui.QKeySequence__NativeText))
	w.createAction.SetStatusTip("Create a new encrypted vault")

	w.openAction = fileMenu.AddAction("&Open Vault...")
	w.openAction.SetShortcut(gui.NewQKeySequence2("Ctrl+O", gui.QKeySequence__NativeText))
	w.openAction.SetStatusTip("Open an existing vault")

	w.closeAction = fileMenu.AddAction("&Close Vault")
	w.closeAction.SetShortcut(gui.NewQKeySequence2("Ctrl+W", gui.QKeySequence__NativeText))
	w.closeAction.SetStatusTip("Close the selected vault")
	w.closeAction.SetEnabled(false)

	fileMenu.AddSeparator()

	w.exitAction = fileMenu.AddAction("E&xit")
	w.exitAction.SetShortcut(gui.NewQKeySequence2("Ctrl+Q", gui.QKeySequence__NativeText))
	w.exitAction.SetStatusTip("Exit the application")

	// Tools menu
	toolsMenu := w.menuBar.AddMenu2("&Tools")

	w.settingsAction = toolsMenu.AddAction("&Settings...")
	w.settingsAction.SetStatusTip("Open application settings")

	// Help menu
	helpMenu := w.menuBar.AddMenu2("&Help")

	w.aboutAction = helpMenu.AddAction("&About...")
	w.aboutAction.SetStatusTip("About dirLocker")
}

// setupToolBar creates the toolbar
func (w *MainWindow) setupToolBar() {
	w.toolbar = w.AddToolBar("Main")

	w.toolbar.AddAction(w.createAction)
	w.toolbar.AddAction(w.openAction)
	w.toolbar.AddAction(w.closeAction)
	w.toolbar.AddSeparator()
	w.toolbar.AddAction(w.settingsAction)
}

// connectSignals connects UI signals to handlers
func (w *MainWindow) connectSignals() {
	w.createAction.ConnectTriggered(func(bool) {
		w.showCreateVaultDialog()
	})

	w.openAction.ConnectTriggered(func(bool) {
		w.showOpenVaultDialog()
	})

	w.closeAction.ConnectTriggered(func(bool) {
		w.closeSelectedVault()
	})

	w.settingsAction.ConnectTriggered(func(bool) {
		w.showSettingsDialog()
	})

	w.aboutAction.ConnectTriggered(func(bool) {
		w.showAboutDialog()
	})

	w.exitAction.ConnectTriggered(func(bool) {
		w.Close()
	})

	w.vaultList.ConnectItemSelectionChanged(func() {
		hasSelection := len(w.vaultList.SelectedItems()) > 0
		w.closeAction.SetEnabled(hasSelection)
	})

	w.vaultList.ConnectItemDoubleClicked(func(item *widgets.QListWidgetItem) {
		// Double-click to show vault details
		w.showVaultDetails(item.Text())
	})
}

// updateVaultList refreshes the vault list display
func (w *MainWindow) updateVaultList() {
	w.vaultList.Clear()

	openVaults := w.vaultManager.ListOpenVaults()
	for _, vaultPath := range openVaults {
		item := widgets.NewQListWidgetItem(nil, 0)
		item.SetText(filepath.Base(vaultPath))
		item.SetToolTip(vaultPath)

		// Set icon based on vault type
		managedVault, _ := w.vaultManager.GetVault(vaultPath)
		_, _, _, isShared := managedVault.GetInfo()
		
		if isShared {
			item.SetData(int(core.Qt__UserRole), core.NewQVariant1("shared"))
		} else {
			item.SetData(int(core.Qt__UserRole), core.NewQVariant1("personal"))
		}

		w.vaultList.AddItem(item)
	}

	// Update status bar
	count := len(openVaults)
	if count == 0 {
		w.statusBar.ShowMessage("No vaults open", 0)
	} else if count == 1 {
		w.statusBar.ShowMessage("1 vault open", 0)
	} else {
		w.statusBar.ShowMessage(fmt.Sprintf("%d vaults open", count), 0)
	}
}

// Dialog methods (simplified implementations)

func (w *MainWindow) showCreateVaultDialog() {
	w.logger.Info("Opening create vault dialog")
	showInfoDialog(w, "Create Vault", "Create vault dialog will be implemented in task 12.")
}

func (w *MainWindow) showOpenVaultDialog() {
	w.logger.Info("Opening open vault dialog")
	showInfoDialog(w, "Open Vault", "Open vault dialog will be implemented in task 12.")
}

func (w *MainWindow) closeSelectedVault() {
	selectedItems := w.vaultList.SelectedItems()
	if len(selectedItems) == 0 {
		return
	}

	item := selectedItems[0]
	vaultPath := item.ToolTip()

	w.logger.Info("Closing vault from GUI", "path", vaultPath)

	if err := w.vaultManager.CloseVault(vaultPath); err != nil {
		showErrorDialog(w, "Error", fmt.Sprintf("Failed to close vault: %v", err))
		return
	}

	w.updateVaultList()
	showInfoDialog(w, "Success", fmt.Sprintf("Vault closed: %s", filepath.Base(vaultPath)))
}

func (w *MainWindow) showVaultDetails(vaultName string) {
	w.logger.Info("Showing vault details", "name", vaultName)
	showInfoDialog(w, "Vault Details", "Vault details dialog will be implemented in task 12.")
}

func (w *MainWindow) showSettingsDialog() {
	w.logger.Info("Opening settings dialog")
	showInfoDialog(w, "Settings", "Settings dialog will be implemented in task 12.")
}

func (w *MainWindow) showAboutDialog() {
	aboutText := fmt.Sprintf(`<h3>dirLocker %s</h3>
<p>Encrypted vault application for secure file storage.</p>
<p><b>Version:</b> %s<br>
<b>Commit:</b> %s<br>
<b>Built:</b> %s</p>
<p>Built with Go and Qt.</p>`, version, version, commit, date)

	widgets.QMessageBox_About(w, "About dirLocker", aboutText)
}

// SystemTrayIcon represents the system tray icon
type SystemTrayIcon struct {
	*widgets.QSystemTrayIcon

	mainWindow   *MainWindow
	vaultManager *vault.VaultManager
	logger       *logging.Logger
}

// NewSystemTrayIcon creates a new system tray icon
func NewSystemTrayIcon(mainWindow *MainWindow, vaultManager *vault.VaultManager, logger *logging.Logger) *SystemTrayIcon {
	tray := &SystemTrayIcon{
		QSystemTrayIcon: widgets.NewQSystemTrayIcon(nil),
		mainWindow:      mainWindow,
		vaultManager:    vaultManager,
		logger:          logger,
	}

	tray.setupTrayIcon()
	return tray
}

// setupTrayIcon initializes the system tray icon
func (t *SystemTrayIcon) setupTrayIcon() {
	// Set icon
	icon := gui.NewQIcon5(":/icons/vault.png") // Placeholder icon path
	t.SetIcon(icon)
	t.SetToolTip("dirLocker - Encrypted Vault Manager")

	// Create context menu
	menu := widgets.NewQMenu(nil)

	showAction := menu.AddAction("Show Window")
	showAction.ConnectTriggered(func(bool) {
		t.mainWindow.Show()
		t.mainWindow.Raise()
		t.mainWindow.ActivateWindow()
	})

	menu.AddSeparator()

	exitAction := menu.AddAction("Exit")
	exitAction.ConnectTriggered(func(bool) {
		t.mainWindow.Close()
	})

	t.SetContextMenu(menu)

	// Connect activation signal
	t.ConnectActivated(func(reason widgets.QSystemTrayIcon__ActivationReason) {
		if reason == widgets.QSystemTrayIcon__DoubleClick {
			t.mainWindow.Show()
			t.mainWindow.Raise()
			t.mainWindow.ActivateWindow()
		}
	})
}

// Utility functions

func showErrorDialog(parent widgets.QWidget_ITF, title, message string) {
	widgets.QMessageBox_Critical(parent, title, message, widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
}

func showInfoDialog(parent widgets.QWidget_ITF, title, message string) {
	widgets.QMessageBox_Information(parent, title, message, widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
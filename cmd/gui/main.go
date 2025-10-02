//go:build !nogui
// +build !nogui

package main

import (
	"fmt"
	"os"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/driver/desktop"

	"dirLocker/internal/gui"
	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

var (
	version = "dev"
)

func main() {
	// Create Fyne application
	fyneApp := app.NewWithID("com.dirlocker.app")

	// Set application metadata
	fyneApp.SetIcon(gui.GetAppIcon())

	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	// Initialize vault manager
	vaultManager, err := vault.NewVaultManager(cfg, logger)
	if err != nil {
		logger.Error("Failed to initialize vault manager", "error", err)
		os.Exit(1)
	}
	defer vaultManager.CloseAllVaults()

	// Start auto-close timer
	vaultManager.StartAutoCloseTimer()

	// Create main window
	mainWindow := gui.NewMainWindow(fyneApp, vaultManager, cfg, logger)

	// Setup system tray if supported
	var systemTray *gui.SystemTray
	if _, ok := fyneApp.(desktop.App); ok {
		systemTray = gui.NewSystemTray(fyneApp, mainWindow, vaultManager, logger)
		_ = systemTray // Use systemTray to avoid unused variable warning
	}

	// Set up window close handler
	mainWindow.SetOnClosed(func() {
		logger.Info("GUI application closing")
		vaultManager.CloseAllVaults()
		fyneApp.Quit()
	})

	logger.Info("GUI application started", "version", version)

	// Show main window and run application
	mainWindow.Show()
	fyneApp.Run()
}

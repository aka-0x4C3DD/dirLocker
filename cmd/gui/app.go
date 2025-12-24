package main

import (
	"context"
	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
	"fmt"
)

// App struct
type App struct {
	ctx          context.Context
	vaultManager *vault.VaultManager
	logger       *logging.Logger
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Initialize configuration
	cfg := config.DefaultConfig()

	// Initialize logging
	logConfig := &logging.LogConfig{
		Level:   "info",
		Console: true,
	}
	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		return
	}
	a.logger = logger

	// Initialize Vault Manager
	vm, err := vault.NewVaultManager(cfg, logger)
	if err != nil {
		logger.Error("Failed to initialize Vault Manager", "error", err)
		return
	}
	a.vaultManager = vm

	logger.Info("GUI Application started")
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

// CreateVault creates a new vault
func (a *App) CreateVault(path, password string) error {
	if a.vaultManager == nil {
		return fmt.Errorf("vault manager not initialized")
	}

	// Default to XChaCha20Poly1305 for new vaults
	return a.vaultManager.CreateVault(path, password, vault.CipherXChaCha20Poly1305)
}

// OpenVault opens an existing vault
func (a *App) OpenVault(path, password string) error {
	if a.vaultManager == nil {
		return fmt.Errorf("vault manager not initialized")
	}

	_, err := a.vaultManager.OpenVault(path, password)
	return err
}

// ListFiles lists files in a vault
func (a *App) ListFiles(path string) ([]vault.FileEntry, error) {
	if a.vaultManager == nil {
		return nil, fmt.Errorf("vault manager not initialized")
	}

	return a.vaultManager.ListFiles(path)
}

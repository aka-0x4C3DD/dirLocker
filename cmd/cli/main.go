package main

import (
	"fmt"
	"os"
	"path/filepath"

	"dirLocker/cmd/cli/commands"
	"dirLocker/pkg/config"
	"dirLocker/pkg/iconmanager"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logConfig := &logging.LogConfig{
		Level:   cfg.LogLevel,
		File:    cfg.GetLogPath(),
		Console: true,
	}
	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Close()

	// Initialize vault manager
	vaultManager, err := vault.NewVaultManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize vault manager: %w", err)
	}
	defer vaultManager.CloseAllVaults()

	// Initialize icon manager and apply custom icon if available
	if err := initializeIconManager(logger); err != nil {
		logger.WithError(err).Warn("Failed to initialize icon manager")
	}

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "dirlocker",
		Short: "Encrypted vault application for secure file storage",
		Long: `dirLocker is a cross-platform encrypted vault application that provides
secure file storage using modern encryption algorithms. It supports both
AES-256-GCM and XChaCha20-Poly1305 encryption with Argon2id key derivation.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Update log level if specified
			if logLevel, _ := cmd.Flags().GetString("log-level"); logLevel != "" {
				logger.SetLevel(logLevel)
			}
		},
	}

	// Global flags
	rootCmd.PersistentFlags().String("config", "", "config file path")
	rootCmd.PersistentFlags().String("log-level", cfg.LogLevel, "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().Bool("verbose", false, "enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(commands.NewCreateCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewOpenCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewCloseCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewListCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewInfoCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewPasswordCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewRecoveryCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewShareCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewMountCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewPushCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewRepairCommand(vaultManager, logger))
	rootCmd.AddCommand(commands.NewConfigCommand(cfg, logger))
	rootCmd.AddCommand(commands.NewIconCommand(logger))
	rootCmd.AddCommand(commands.NewMountHelperCommand(logger))

	// Execute root command
	return rootCmd.Execute()
}

// initializeIconManager initializes the icon manager and applies custom icons if available
func initializeIconManager(logger *logging.Logger) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	appDir := filepath.Dir(execPath)
	config := iconmanager.IconManagerConfig{
		AppDir:                appDir,
		EnableChangeDetection: true,
	}

	iconMgr := iconmanager.NewIconManagerWithCustomLogger(config, logger)

	// Detect and apply custom icon
	customIcon, err := iconMgr.DetectCustomIcon()
	if err != nil {
		logger.WithError(err).Debug("Failed to detect custom icon")
		return nil // Don't fail startup for icon issues
	}

	if err := iconMgr.ApplyIcon(customIcon); err != nil {
		logger.WithError(err).Debug("Failed to apply icon")
		return nil // Don't fail startup for icon issues
	}

	if customIcon == "" {
		logger.Debug("Using default application icon")
	} else {
		logger.Infof("Using custom icon: %s", customIcon)
	}

	return nil
}

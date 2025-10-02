//go:build windows
// +build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dirLocker/internal/dokany"
	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

func main() {
	var (
		vaultPath   = flag.String("vault", "", "Path to vault file")
		driveLetter = flag.String("drive", "", "Drive letter to mount (e.g., Z:)")
		password    = flag.String("password", "", "Vault password (use with caution)")
		readOnly    = flag.Bool("readonly", false, "Mount as read-only")
		debug       = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	if *vaultPath == "" || *driveLetter == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --vault <vault-file> --drive <drive-letter> [options]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Set up logging
	logConfig := &logging.LogConfig{
		Level:   "info",
		Console: true,
	}
	if *debug {
		logConfig.Level = "debug"
	}

	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}

	logger.Info("Starting dirLocker Dokany daemon",
		"vault", *vaultPath,
		"drive", *driveLetter,
		"readonly", *readOnly)

	// Get password if not provided
	if *password == "" {
		fmt.Print("Enter vault password: ")
		passwordBytes, err := readPassword()
		if err != nil {
			logger.Error("Failed to read password", "error", err)
			os.Exit(1)
		}
		*password = string(passwordBytes)
	}

	// Load configuration
	cfg := config.DefaultConfig()

	// Open vault
	vaultManager, err := vault.NewVaultManager(cfg, logger)
	if err != nil {
		logger.Error("Failed to create vault manager", "error", err)
		os.Exit(1)
	}

	v, err := vaultManager.OpenVault(*vaultPath, *password)
	if err != nil {
		logger.Error("Failed to open vault", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := vaultManager.CloseVault(*vaultPath); err != nil {
			logger.Error("Failed to close vault", "error", err)
		}
	}()

	// Set up Dokany filesystem
	fs, err := dokany.NewVaultFS(v, logger, &dokany.Options{
		ReadOnly: *readOnly,
		Debug:    *debug,
	})
	if err != nil {
		logger.Error("Failed to create Dokany filesystem", "error", err)
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Mount and serve
	logger.Info("Mounting Dokany filesystem", "drive", *driveLetter)
	if err := fs.Mount(ctx, *driveLetter); err != nil {
		logger.Error("Failed to mount filesystem", "error", err)
		os.Exit(1)
	}

	logger.Info("Dokany filesystem mounted successfully")

	// Wait for shutdown signal
	<-ctx.Done()

	// Unmount
	logger.Info("Unmounting filesystem")
	if err := fs.Unmount(); err != nil {
		logger.Error("Failed to unmount filesystem", "error", err)
	}

	logger.Info("dirLocker Dokany daemon stopped")
}

func readPassword() ([]byte, error) {
	// This is a simplified password reading function
	// In a real implementation, you'd want to use a proper terminal library
	// to hide the password input
	var password string
	_, err := fmt.Scanln(&password)
	return []byte(password), err
}

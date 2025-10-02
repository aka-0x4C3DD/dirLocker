//go:build linux || darwin
// +build linux darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dirLocker/internal/fuse"
	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"
)

func main() {
	var (
		vaultPath  = flag.String("vault", "", "Path to vault file")
		mountPoint = flag.String("mountpoint", "", "Mount point directory")
		password   = flag.String("password", "", "Vault password (use with caution)")
		readOnly   = flag.Bool("readonly", false, "Mount as read-only")
		allowOther = flag.Bool("allow-other", false, "Allow other users to access mount")
		debug      = flag.Bool("debug", false, "Enable debug logging")
		_          = flag.String("fuse-option", "", "Additional FUSE options (can be repeated)") // TODO: implement FUSE options
	)
	flag.Parse()

	if *vaultPath == "" || *mountPoint == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --vault <vault-file> --mountpoint <mount-point> [options]\n", os.Args[0])
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

	logger.Info("Starting dirLocker FUSE daemon",
		"vault", *vaultPath,
		"mountpoint", *mountPoint,
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

	// Create mount point if it doesn't exist
	if err := os.MkdirAll(*mountPoint, 0755); err != nil {
		logger.Error("Failed to create mount point", "error", err)
		os.Exit(1)
	}

	// Set up FUSE filesystem
	fs, err := fuse.NewVaultFS(v, logger, &fuse.Options{
		ReadOnly:   *readOnly,
		AllowOther: *allowOther,
		Debug:      *debug,
	})
	if err != nil {
		logger.Error("Failed to create FUSE filesystem", "error", err)
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
	logger.Info("Mounting FUSE filesystem", "mountpoint", *mountPoint)
	if err := fs.Mount(ctx, *mountPoint); err != nil {
		logger.Error("Failed to mount filesystem", "error", err)
		os.Exit(1)
	}

	logger.Info("FUSE filesystem mounted successfully")

	// Wait for shutdown signal
	<-ctx.Done()

	// Unmount
	logger.Info("Unmounting filesystem")
	if err := fs.Unmount(); err != nil {
		logger.Error("Failed to unmount filesystem", "error", err)
	}

	logger.Info("dirLocker FUSE daemon stopped")
}

func readPassword() ([]byte, error) {
	// This is a simplified password reading function
	// In a real implementation, you'd want to use a proper terminal library
	// to hide the password input
	var password string
	_, err := fmt.Scanln(&password)
	return []byte(password), err
}

//go:build windows

package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dirLocker/internal/dokany"
	"dirLocker/internal/winfsp"
	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewMountHelperCommand creates the hidden 'mount-helper' command
func NewMountHelperCommand(logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "mount-helper",
		Short:  "Internal mount helper",
		Hidden: true,
	}

	cmd.AddCommand(newDokanyHelperCommand(logger))
	cmd.AddCommand(newWinFSPHelperCommand(logger))

	return cmd
}

func newDokanyHelperCommand(logger *logging.Logger) *cobra.Command {
	var (
		vaultPath   string
		driveLetter string
		password    string
		readOnly    bool
		debug       bool
	)

	cmd := &cobra.Command{
		Use:   "dokany",
		Short: "Dokany mount helper",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMountHelper(logger, "dokany", vaultPath, driveLetter, password, readOnly, debug)
		},
	}

	cmd.Flags().StringVar(&vaultPath, "vault", "", "Path to vault file")
	cmd.Flags().StringVar(&driveLetter, "drive", "", "Drive letter to mount")
	cmd.Flags().StringVar(&password, "password", "", "Vault password")
	cmd.Flags().BoolVar(&readOnly, "readonly", false, "Mount as read-only")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")

	return cmd
}

func newWinFSPHelperCommand(logger *logging.Logger) *cobra.Command {
	var (
		vaultPath   string
		driveLetter string
		password    string
		readOnly    bool
		debug       bool
	)

	cmd := &cobra.Command{
		Use:   "winfsp",
		Short: "WinFSP mount helper",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMountHelper(logger, "winfsp", vaultPath, driveLetter, password, readOnly, debug)
		},
	}

	cmd.Flags().StringVar(&vaultPath, "vault", "", "Path to vault file")
	cmd.Flags().StringVar(&driveLetter, "drive", "", "Drive letter to mount")
	cmd.Flags().StringVar(&password, "password", "", "Vault password")
	cmd.Flags().BoolVar(&readOnly, "readonly", false, "Mount as read-only")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")

	return cmd
}

func runMountHelper(logger *logging.Logger, driverType, vaultPath, mountPoint, password string, readOnly, debug bool) error {
	if vaultPath == "" || mountPoint == "" {
		return fmt.Errorf("vault path and mount point are required")
	}

	if debug {
		logger.SetLevel("debug")
	}

	cfg := config.DefaultConfig()
	vaultManager, err := vault.NewVaultManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to create vault manager: %w", err)
	}

	v, err := vaultManager.OpenVault(vaultPath, password)
	if err != nil {
		return fmt.Errorf("failed to open vault: %w", err)
	}
	defer vaultManager.CloseVault(vaultPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	var fs interface {
		Mount(context.Context, string) error
		Unmount() error
	}

	logger.Info("Starting mount helper", "driver", driverType, "mountpoint", mountPoint)

	switch driverType {
	case "dokany":
		fs, err = dokany.NewVaultFS(v, logger, &dokany.Options{
			ReadOnly: readOnly,
			Debug:    debug,
		})
	case "winfsp":
		fs, err = winfsp.NewVaultFS(v, logger, &winfsp.Options{
			ReadOnly: readOnly,
			Debug:    debug,
		})
	default:
		return fmt.Errorf("unknown driver type: %s", driverType)
	}

	if err != nil {
		return fmt.Errorf("failed to create filesystem: %w", err)
	}

	if err := fs.Mount(ctx, mountPoint); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}

	// Wait for context cancellation (signal or error)
	<-ctx.Done()

	if err := fs.Unmount(); err != nil {
		logger.Error("Unmount failed", "error", err)
	}

	return nil
}

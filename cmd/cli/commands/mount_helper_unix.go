//go:build !windows

package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dirLocker/internal/fuse"
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

	cmd.AddCommand(newFuseHelperCommand(logger))

	return cmd
}

func newFuseHelperCommand(logger *logging.Logger) *cobra.Command {
	var (
		vaultPath  string
		mountPoint string
		password   string
		readOnly   bool
		allowOther bool
		debug      bool
	)

	cmd := &cobra.Command{
		Use:   "fuse",
		Short: "FUSE mount helper",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			if err := os.MkdirAll(mountPoint, 0755); err != nil {
				return fmt.Errorf("failed to create mount point: %w", err)
			}

			fs, err := fuse.NewVaultFS(v, logger, &fuse.Options{
				ReadOnly:   readOnly,
				AllowOther: allowOther,
				Debug:      debug,
			})
			if err != nil {
				return fmt.Errorf("failed to create FUSE filesystem: %w", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				sig := <-sigChan
				logger.Info("Received signal, shutting down", "signal", sig)
				cancel()
			}()

			logger.Info("Mounting FUSE filesystem", "mountpoint", mountPoint)
			if err := fs.Mount(ctx, mountPoint); err != nil {
				return fmt.Errorf("failed to mount: %w", err)
			}

			if err := fs.Unmount(); err != nil {
				logger.Error("Failed to unmount", "error", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&vaultPath, "vault", "", "Path to vault file")
	cmd.Flags().StringVar(&mountPoint, "mountpoint", "", "Mount point directory")
	cmd.Flags().StringVar(&password, "password", "", "Vault password")
	cmd.Flags().BoolVar(&readOnly, "readonly", false, "Mount as read-only")
	cmd.Flags().BoolVar(&allowOther, "allow-other", false, "Allow other users")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
	cmd.Flags().StringArray("fuse-option", []string{}, "FUSE mount options (key=value)")

	return cmd
}

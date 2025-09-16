package commands

import (
	"fmt"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewMountCommand creates the 'mount' command
func NewMountCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mount",
		Short: "Filesystem mounting operations",
		Long:  `Mount and unmount vaults as filesystem drives.`,
	}

	// Add subcommands
	cmd.AddCommand(newMountVaultCommand(vaultManager, logger))
	cmd.AddCommand(newUnmountVaultCommand(vaultManager, logger))

	return cmd
}

func newMountVaultCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var mountPoint string

	cmd := &cobra.Command{
		Use:   "vault [vault-path]",
		Short: "Mount a vault as a filesystem",
		Long:  `Mount an open vault as a filesystem drive for direct file access.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Check if vault is open
			_, exists := vaultManager.GetVault(vaultPath)
			if !exists {
				return fmt.Errorf("vault is not open: %s (use 'dirlocker open' first)", vaultPath)
			}

			if mountPoint == "" {
				return fmt.Errorf("mount point is required")
			}

			logger.Info("Mounting vault", "path", vaultPath, "mount_point", mountPoint)

			// This is a placeholder for the actual mounting implementation
			// which will be implemented in later tasks
			fmt.Printf("Mounting functionality will be implemented in task 14.\n")
			fmt.Printf("Would mount vault: %s\n", vaultPath)
			fmt.Printf("At mount point: %s\n", mountPoint)

			return nil
		},
	}

	cmd.Flags().StringVarP(&mountPoint, "mount-point", "m", "", "filesystem mount point")
	cmd.MarkFlagRequired("mount-point")

	return cmd
}

func newUnmountVaultCommand(_ *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unmount [mount-point]",
		Short: "Unmount a vault filesystem",
		Long:  `Unmount a previously mounted vault filesystem.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mountPoint := args[0]

			logger.Info("Unmounting vault", "mount_point", mountPoint)

			// This is a placeholder for the actual unmounting implementation
			// which will be implemented in later tasks
			fmt.Printf("Unmounting functionality will be implemented in task 14.\n")
			fmt.Printf("Would unmount: %s\n", mountPoint)

			return nil
		},
	}

	return cmd
}

package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/mount"
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
	cmd.AddCommand(newListMountsCommand(vaultManager, logger))
	cmd.AddCommand(newMountStatusCommand(vaultManager, logger))

	return cmd
}

func newMountVaultCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var (
		mountPoint string
		readOnly   bool
		allowOther bool
		fsName     string
		options    []string
	)

	cmd := &cobra.Command{
		Use:   "vault [vault-path]",
		Short: "Mount a vault as a filesystem",
		Long:  `Mount an open vault as a filesystem drive for direct file access.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Check if mounting is supported
			if !vaultManager.IsMountingSupported() {
				fmt.Printf("Mounting is not supported on this platform.\n")
				fmt.Printf("Required drivers: %s\n", strings.Join(vaultManager.GetRequiredMountDrivers(), ", "))
				fmt.Printf("\nTroubleshooting:\n%s\n", vaultManager.GetMountTroubleshootingInfo())
				return fmt.Errorf("mounting not supported")
			}

			// Check drivers
			if err := vaultManager.CheckMountDrivers(); err != nil {
				fmt.Printf("Mount drivers not available: %v\n", err)
				fmt.Printf("Required drivers: %s\n", strings.Join(vaultManager.GetRequiredMountDrivers(), ", "))
				fmt.Printf("\nTroubleshooting:\n%s\n", vaultManager.GetMountTroubleshootingInfo())
				return fmt.Errorf("mount drivers not available: %w", err)
			}

			// Check if vault is open
			_, exists := vaultManager.GetVault(vaultPath)
			if !exists {
				return fmt.Errorf("vault is not open: %s (use 'dirlocker open' first)", vaultPath)
			}

			if mountPoint == "" {
				return fmt.Errorf("mount point is required")
			}

			// Validate mount point
			if err := validateMountPoint(mountPoint); err != nil {
				return fmt.Errorf("invalid mount point: %w", err)
			}

			logger.Info("Mounting vault", "path", vaultPath, "mount_point", mountPoint, "platform", runtime.GOOS)

			// Display mount information
			fmt.Printf("Mounting vault: %s\n", vaultPath)
			fmt.Printf("Mount point: %s\n", mountPoint)
			fmt.Printf("Platform: %s\n", runtime.GOOS)
			fmt.Printf("Read-only: %t\n", readOnly)
			fmt.Printf("Allow other users: %t\n", allowOther)

			if fsName != "" {
				fmt.Printf("Filesystem name: %s\n", fsName)
			}

			if len(options) > 0 {
				fmt.Printf("Mount options: %s\n", strings.Join(options, ","))
			}

			// Create mount options
			mountOptions := &mount.MountOptions{
				MountPoint:   mountPoint,
				ReadOnly:     readOnly,
				AllowOther:   allowOther,
				Timeout:      60 * time.Second,
				Debug:        false,
				CacheTimeout: 1 * time.Second,
			}

			// Perform the mount
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()

			fmt.Printf("\nMounting...")
			mountInfo, err := vaultManager.MountVault(ctx, vaultPath, mountPoint, mountOptions)
			if err != nil {
				fmt.Printf(" FAILED\n")
				fmt.Printf("Error: %v\n", err)
				fmt.Printf("\nTroubleshooting:\n%s\n", vaultManager.GetMountTroubleshootingInfo())
				return fmt.Errorf("failed to mount vault: %w", err)
			}

			fmt.Printf(" SUCCESS\n")
			fmt.Printf("\nMount Information:\n")
			fmt.Printf("  Vault Path: %s\n", mountInfo.VaultPath)
			fmt.Printf("  Mount Point: %s\n", mountInfo.MountPoint)
			fmt.Printf("  Mounted At: %s\n", mountInfo.MountedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Read Only: %t\n", mountInfo.ReadOnly)
			fmt.Printf("  Filesystem: %s\n", mountInfo.FileSystem)
			fmt.Printf("  Process ID: %d\n", mountInfo.ProcessID)

			fmt.Printf("\nVault is now accessible at: %s\n", mountInfo.MountPoint)
			fmt.Printf("Use 'dirlocker mount unmount %s' to unmount when finished.\n", mountInfo.MountPoint)

			return nil
		},
	}

	cmd.Flags().StringVarP(&mountPoint, "mount-point", "m", "", "filesystem mount point")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "mount as read-only")
	cmd.Flags().BoolVar(&allowOther, "allow-other", false, "allow other users to access the mount")
	cmd.Flags().StringVar(&fsName, "fs-name", "", "filesystem name/label")
	cmd.Flags().StringSliceVarP(&options, "option", "o", nil, "additional mount options")
	cmd.MarkFlagRequired("mount-point")

	return cmd
}

func newUnmountVaultCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "unmount [mount-point]",
		Short: "Unmount a vault filesystem",
		Long:  `Unmount a previously mounted vault filesystem.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mountPoint := args[0]

			// Check if mounting is supported
			if !vaultManager.IsMountingSupported() {
				return fmt.Errorf("mounting not supported on this platform")
			}

			logger.Info("Unmounting vault", "mount_point", mountPoint, "force", force)

			fmt.Printf("Unmounting: %s\n", mountPoint)
			fmt.Printf("Platform: %s\n", runtime.GOOS)
			fmt.Printf("Force unmount: %t\n", force)

			// Check if mount point is actually mounted
			isMounted, err := vaultManager.IsVaultMounted(mountPoint)
			if err != nil {
				return fmt.Errorf("failed to check mount status: %w", err)
			}

			if !isMounted {
				fmt.Printf("Mount point is not currently mounted: %s\n", mountPoint)
				return nil
			}

			// Get mount info before unmounting
			mountInfo, err := vaultManager.GetMountInfo(mountPoint)
			if err != nil {
				fmt.Printf("Warning: Could not get mount info: %v\n", err)
			} else {
				fmt.Printf("Vault: %s\n", mountInfo.VaultPath)
				fmt.Printf("Filesystem: %s\n", mountInfo.FileSystem)
			}

			// Perform the unmount
			timeout := 30 * time.Second
			if force {
				timeout = 10 * time.Second // Shorter timeout for force unmount
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			fmt.Printf("\nUnmounting...")
			if err := vaultManager.UnmountVault(ctx, mountPoint); err != nil {
				fmt.Printf(" FAILED\n")
				fmt.Printf("Error: %v\n", err)
				return fmt.Errorf("failed to unmount vault: %w", err)
			}

			fmt.Printf(" SUCCESS\n")
			fmt.Printf("Vault has been unmounted from: %s\n", mountPoint)

			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "force unmount even if busy")

	return cmd
}

func newListMountsCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List mounted vaults",
		Long:  `List all currently mounted vault filesystems.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Listing mounted vaults")

			// Check if mounting is supported
			if !vaultManager.IsMountingSupported() {
				fmt.Printf("Mounting is not supported on this platform.\n")
				return nil
			}

			fmt.Printf("Mounted vaults:\n")
			fmt.Printf("Platform: %s\n\n", runtime.GOOS)

			// Get list of mounted vaults
			mounts, err := vaultManager.ListMountedVaults()
			if err != nil {
				return fmt.Errorf("failed to list mounted vaults: %w", err)
			}

			if len(mounts) == 0 {
				fmt.Printf("No vaults are currently mounted.\n")
				return nil
			}

			// Display mounted vaults
			for i, mountInfo := range mounts {
				fmt.Printf("%d. Mount Point: %s\n", i+1, mountInfo.MountPoint)
				fmt.Printf("   Vault Path: %s\n", mountInfo.VaultPath)
				fmt.Printf("   Mounted At: %s\n", mountInfo.MountedAt.Format("2006-01-02 15:04:05"))
				fmt.Printf("   Read Only: %t\n", mountInfo.ReadOnly)
				fmt.Printf("   Filesystem: %s\n", mountInfo.FileSystem)
				fmt.Printf("   Process ID: %d\n", mountInfo.ProcessID)
				fmt.Printf("\n")
			}

			fmt.Printf("Total mounted vaults: %d\n", len(mounts))

			return nil
		},
	}

	return cmd
}

func newMountStatusCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status [mount-point]",
		Short: "Check mount status",
		Long:  `Check the status of a specific mount point.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mountPoint := args[0]

			logger.Info("Checking mount status", "mount_point", mountPoint)

			fmt.Printf("Checking mount status: %s\n", mountPoint)
			fmt.Printf("Platform: %s\n", runtime.GOOS)

			// Check if mounting is supported
			if !vaultManager.IsMountingSupported() {
				fmt.Printf("Status: Mounting not supported on this platform\n")
				return nil
			}

			// Check if mount point exists
			if _, err := os.Stat(mountPoint); os.IsNotExist(err) {
				fmt.Printf("Status: Mount point does not exist\n")
				return nil
			}

			// Check if mounted
			isMounted, err := vaultManager.IsVaultMounted(mountPoint)
			if err != nil {
				return fmt.Errorf("failed to check mount status: %w", err)
			}

			if !isMounted {
				fmt.Printf("Status: Not mounted\n")
				return nil
			}

			fmt.Printf("Status: Mounted\n")

			// Get detailed mount information
			mountInfo, err := vaultManager.GetMountInfo(mountPoint)
			if err != nil {
				fmt.Printf("Warning: Could not get detailed mount info: %v\n", err)
				return nil
			}

			fmt.Printf("\nMount Details:\n")
			fmt.Printf("  Vault Path: %s\n", mountInfo.VaultPath)
			fmt.Printf("  Mount Point: %s\n", mountInfo.MountPoint)
			fmt.Printf("  Mounted At: %s\n", mountInfo.MountedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Read Only: %t\n", mountInfo.ReadOnly)
			fmt.Printf("  Filesystem: %s\n", mountInfo.FileSystem)
			fmt.Printf("  Process ID: %d\n", mountInfo.ProcessID)

			// Calculate uptime
			uptime := time.Since(mountInfo.MountedAt)
			fmt.Printf("  Uptime: %s\n", uptime.Round(time.Second))

			return nil
		},
	}

	return cmd
}

// Helper functions for platform-specific mounting

func validateMountPoint(mountPoint string) error {
	switch runtime.GOOS {
	case "windows":
		// Windows drive letters or UNC paths
		if len(mountPoint) == 2 && mountPoint[1] == ':' {
			// Drive letter like "Z:"
			return nil
		}
		if strings.HasPrefix(mountPoint, "\\\\") {
			// UNC path
			return nil
		}
		if filepath.IsAbs(mountPoint) {
			// Absolute path
			return nil
		}
		return fmt.Errorf("invalid Windows mount point: %s (use drive letter like Z: or absolute path)", mountPoint)

	case "linux", "darwin":
		// Unix-like systems require absolute paths
		if !filepath.IsAbs(mountPoint) {
			return fmt.Errorf("mount point must be an absolute path: %s", mountPoint)
		}
		return nil

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

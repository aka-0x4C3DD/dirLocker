package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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

			// Platform-specific mounting logic
			switch runtime.GOOS {
			case "windows":
				return mountWindows(vaultPath, mountPoint, readOnly, allowOther, fsName, options, logger)
			case "linux":
				return mountLinux(vaultPath, mountPoint, readOnly, allowOther, fsName, options, logger)
			case "darwin":
				return mountMacOS(vaultPath, mountPoint, readOnly, allowOther, fsName, options, logger)
			default:
				return fmt.Errorf("mounting not supported on platform: %s", runtime.GOOS)
			}
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

			logger.Info("Unmounting vault", "mount_point", mountPoint, "force", force)

			fmt.Printf("Unmounting: %s\n", mountPoint)
			fmt.Printf("Platform: %s\n", runtime.GOOS)
			fmt.Printf("Force unmount: %t\n", force)

			// Platform-specific unmounting logic
			switch runtime.GOOS {
			case "windows":
				return unmountWindows(mountPoint, force, logger)
			case "linux":
				return unmountLinux(mountPoint, force, logger)
			case "darwin":
				return unmountMacOS(mountPoint, force, logger)
			default:
				return fmt.Errorf("unmounting not supported on platform: %s", runtime.GOOS)
			}
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

			fmt.Printf("Mounted vaults:\n")
			fmt.Printf("Platform: %s\n\n", runtime.GOOS)

			// This is a placeholder for the actual mount listing implementation
			// which will be implemented in task 14
			fmt.Printf("Mount listing functionality will be implemented in task 14.\n")
			fmt.Printf("This would show:\n")
			fmt.Printf("- Active mount points\n")
			fmt.Printf("- Associated vault files\n")
			fmt.Printf("- Mount options and status\n")

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

			// Check if mount point exists
			if _, err := os.Stat(mountPoint); os.IsNotExist(err) {
				fmt.Printf("Status: Mount point does not exist\n")
				return nil
			}

			// This is a placeholder for the actual mount status implementation
			// which will be implemented in task 14
			fmt.Printf("Mount status functionality will be implemented in task 14.\n")
			fmt.Printf("This would show:\n")
			fmt.Printf("- Mount active/inactive status\n")
			fmt.Printf("- Associated vault file\n")
			fmt.Printf("- Filesystem driver information\n")
			fmt.Printf("- Performance statistics\n")

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

func mountWindows(vaultPath, mountPoint string, readOnly, allowOther bool, fsName string, options []string, logger *logging.Logger) error {
	fmt.Printf("\nWindows Mounting Details:\n")
	fmt.Printf("Driver: WinFsp or Dokany\n")
	fmt.Printf("Mount type: %s\n", map[bool]string{true: "Drive letter", false: "Directory"}[len(mountPoint) == 2])

	if fsName == "" {
		fsName = "dirLocker Vault"
	}

	fmt.Printf("Volume label: %s\n", fsName)

	// This is a placeholder for the actual Windows mounting implementation
	// which will be implemented in task 14
	fmt.Printf("\nWindows mounting functionality will be implemented in task 14.\n")
	fmt.Printf("This would:\n")
	fmt.Printf("- Initialize WinFsp/Dokany driver\n")
	fmt.Printf("- Create filesystem callbacks\n")
	fmt.Printf("- Mount vault at %s\n", mountPoint)
	fmt.Printf("- Handle file operations through vault API\n")

	logger.Info("Windows mount initiated", "vault", vaultPath, "mount_point", mountPoint)
	return nil
}

func mountLinux(vaultPath, mountPoint string, readOnly, allowOther bool, fsName string, options []string, logger *logging.Logger) error {
	fmt.Printf("\nLinux Mounting Details:\n")
	fmt.Printf("Driver: FUSE\n")
	fmt.Printf("Mount point: %s\n", mountPoint)

	// Check if mount point directory exists
	if _, err := os.Stat(mountPoint); os.IsNotExist(err) {
		fmt.Printf("Creating mount point directory: %s\n", mountPoint)
		if err := os.MkdirAll(mountPoint, 0755); err != nil {
			return fmt.Errorf("failed to create mount point: %w", err)
		}
	}

	// Build FUSE options
	fuseOptions := []string{}
	if readOnly {
		fuseOptions = append(fuseOptions, "ro")
	}
	if allowOther {
		fuseOptions = append(fuseOptions, "allow_other")
	}
	fuseOptions = append(fuseOptions, options...)

	if len(fuseOptions) > 0 {
		fmt.Printf("FUSE options: %s\n", strings.Join(fuseOptions, ","))
	}

	// This is a placeholder for the actual Linux mounting implementation
	// which will be implemented in task 14
	fmt.Printf("\nLinux mounting functionality will be implemented in task 14.\n")
	fmt.Printf("This would:\n")
	fmt.Printf("- Initialize FUSE filesystem\n")
	fmt.Printf("- Implement FUSE callbacks\n")
	fmt.Printf("- Mount vault at %s\n", mountPoint)
	fmt.Printf("- Handle file operations through vault API\n")

	logger.Info("Linux mount initiated", "vault", vaultPath, "mount_point", mountPoint)
	return nil
}

func mountMacOS(vaultPath, mountPoint string, readOnly, allowOther bool, fsName string, options []string, logger *logging.Logger) error {
	fmt.Printf("\nmacOS Mounting Details:\n")
	fmt.Printf("Driver: macFUSE\n")
	fmt.Printf("Mount point: %s\n", mountPoint)

	// Check if mount point directory exists
	if _, err := os.Stat(mountPoint); os.IsNotExist(err) {
		fmt.Printf("Creating mount point directory: %s\n", mountPoint)
		if err := os.MkdirAll(mountPoint, 0755); err != nil {
			return fmt.Errorf("failed to create mount point: %w", err)
		}
	}

	if fsName == "" {
		fsName = "dirLocker Vault"
	}
	fmt.Printf("Volume name: %s\n", fsName)

	// Build macFUSE options
	macOptions := []string{}
	if readOnly {
		macOptions = append(macOptions, "ro")
	}
	if allowOther {
		macOptions = append(macOptions, "allow_other")
	}
	macOptions = append(macOptions, "volname="+fsName)
	macOptions = append(macOptions, options...)

	if len(macOptions) > 0 {
		fmt.Printf("macFUSE options: %s\n", strings.Join(macOptions, ","))
	}

	// This is a placeholder for the actual macOS mounting implementation
	// which will be implemented in task 14
	fmt.Printf("\nmacOS mounting functionality will be implemented in task 14.\n")
	fmt.Printf("This would:\n")
	fmt.Printf("- Initialize macFUSE filesystem\n")
	fmt.Printf("- Implement FUSE callbacks\n")
	fmt.Printf("- Mount vault at %s\n", mountPoint)
	fmt.Printf("- Handle file operations through vault API\n")

	logger.Info("macOS mount initiated", "vault", vaultPath, "mount_point", mountPoint)
	return nil
}

func unmountWindows(mountPoint string, force bool, logger *logging.Logger) error {
	fmt.Printf("\nWindows Unmounting Details:\n")
	fmt.Printf("Driver: WinFsp or Dokany\n")

	// This is a placeholder for the actual Windows unmounting implementation
	fmt.Printf("\nWindows unmounting functionality will be implemented in task 14.\n")
	fmt.Printf("This would:\n")
	fmt.Printf("- Signal filesystem to unmount\n")
	if force {
		fmt.Printf("- Force unmount even if files are open\n")
	}
	fmt.Printf("- Clean up driver resources\n")
	fmt.Printf("- Remove mount point %s\n", mountPoint)

	logger.Info("Windows unmount initiated", "mount_point", mountPoint, "force", force)
	return nil
}

func unmountLinux(mountPoint string, force bool, logger *logging.Logger) error {
	fmt.Printf("\nLinux Unmounting Details:\n")
	fmt.Printf("Driver: FUSE\n")

	// This is a placeholder for the actual Linux unmounting implementation
	fmt.Printf("\nLinux unmounting functionality will be implemented in task 14.\n")
	fmt.Printf("This would:\n")
	if force {
		fmt.Printf("- Execute: fusermount -u -z %s\n", mountPoint)
	} else {
		fmt.Printf("- Execute: fusermount -u %s\n", mountPoint)
	}
	fmt.Printf("- Clean up FUSE resources\n")
	fmt.Printf("- Remove mount point if empty\n")

	logger.Info("Linux unmount initiated", "mount_point", mountPoint, "force", force)
	return nil
}

func unmountMacOS(mountPoint string, force bool, logger *logging.Logger) error {
	fmt.Printf("\nmacOS Unmounting Details:\n")
	fmt.Printf("Driver: macFUSE\n")

	// This is a placeholder for the actual macOS unmounting implementation
	fmt.Printf("\nmacOS unmounting functionality will be implemented in task 14.\n")
	fmt.Printf("This would:\n")
	if force {
		fmt.Printf("- Execute: umount -f %s\n", mountPoint)
	} else {
		fmt.Printf("- Execute: umount %s\n", mountPoint)
	}
	fmt.Printf("- Clean up macFUSE resources\n")
	fmt.Printf("- Remove mount point if empty\n")

	logger.Info("macOS unmount initiated", "mount_point", mountPoint, "force", force)
	return nil
}
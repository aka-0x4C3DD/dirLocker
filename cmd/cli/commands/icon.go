package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"dirLocker/pkg/iconmanager"

	"github.com/spf13/cobra"
)

// NewIconCommand creates a new icon management command
func NewIconCommand(logger interface{}) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "icon",
		Short: "Manage application icons",
		Long: `Manage custom application icons for dirLocker.

The icon command allows you to detect, validate, and manage custom .ico files
that can be used as the application icon. Place .ico files in the application
directory to customize the appearance of dirLocker.`,
	}

	// Add subcommands
	cmd.AddCommand(newIconDetectCommand(logger))
	cmd.AddCommand(newIconValidateCommand(logger))
	cmd.AddCommand(newIconInfoCommand(logger))
	cmd.AddCommand(newIconApplyCommand(logger))

	return cmd
}

// newIconDetectCommand creates the icon detect subcommand
func newIconDetectCommand(logger interface{}) *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Detect custom icons in the application directory",
		Long: `Scan the application directory for .ico files and report what was found.

This command will:
- Scan for .ico files in the application directory
- Validate found icons
- Report which icon would be selected if multiple are found
- Show warnings for invalid or multiple icons`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIconDetect(logger)
		},
	}
}

// newIconValidateCommand creates the icon validate subcommand
func newIconValidateCommand(logger interface{}) *cobra.Command {
	return &cobra.Command{
		Use:   "validate <icon-file>",
		Short: "Validate an icon file",
		Long: `Validate that the specified .ico file is properly formatted and can be used
as an application icon.

This command checks:
- ICO file format and signature
- File size limits
- Icon entry count
- File accessibility`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIconValidate(args[0], logger)
		},
	}
}

// newIconInfoCommand creates the icon info subcommand
func newIconInfoCommand(logger interface{}) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show current icon information",
		Long: `Display information about the currently applied icon, including:
- Current icon path (if using custom icon)
- Icon file modification time
- Icon validation status
- Default icon information`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIconInfo(logger)
		},
	}
}

// newIconApplyCommand creates the icon apply subcommand
func newIconApplyCommand(logger interface{}) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply [icon-file]",
		Short: "Apply an icon to the application",
		Long: `Apply the specified icon file to the application, or use the default icon
if no file is specified.

The icon change will take effect on the next application restart.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			iconPath := ""
			if len(args) > 0 {
				iconPath = args[0]
			}
			return runIconApply(iconPath, logger)
		},
	}

	cmd.Flags().Bool("default", false, "Apply the default icon")

	return cmd
}

// runIconDetect implements the icon detect command
func runIconDetect(logger interface{}) error {
	iconManager, err := createIconManager(logger)
	if err != nil {
		return err
	}

	fmt.Println("Scanning for custom icons...")

	customIcon, err := iconManager.DetectCustomIcon()
	if err != nil {
		return fmt.Errorf("failed to detect custom icons: %w", err)
	}

	if customIcon == "" {
		fmt.Println("✓ No custom icons found")
		fmt.Println("  The application will use the default icon")
		return nil
	}

	fmt.Printf("✓ Found custom icon: %s\n", customIcon)

	// Get additional information about the icon
	if info, err := os.Stat(customIcon); err == nil {
		fmt.Printf("  Size: %d bytes\n", info.Size())
		fmt.Printf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
	}

	// Check if there are multiple icons
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	appDir := filepath.Dir(execPath)

	icons, err := scanForAllIcons(appDir)
	if err != nil {
		fmt.Printf("Warning: Failed to scan for all icons: %v\n", err)
	} else if len(icons) > 1 {
		fmt.Printf("⚠ Warning: Multiple .ico files found (%d total)\n", len(icons))
		fmt.Println("  Selected icon is the first alphabetically")
		fmt.Println("  All found icons:")
		for i, icon := range icons {
			marker := "  "
			if icon == customIcon {
				marker = "→ "
			}
			fmt.Printf("  %s%d. %s\n", marker, i+1, filepath.Base(icon))
		}
	}

	return nil
}

// runIconValidate implements the icon validate command
func runIconValidate(iconPath string, logger interface{}) error {
	iconManager, err := createIconManager(logger)
	if err != nil {
		return err
	}

	fmt.Printf("Validating icon: %s\n", iconPath)

	if err := iconManager.ValidateIcon(iconPath); err != nil {
		fmt.Printf("✗ Icon validation failed: %v\n", err)
		return nil // Don't return error to avoid double error message
	}

	fmt.Println("✓ Icon validation successful")

	// Show additional information
	if info, err := os.Stat(iconPath); err == nil {
		fmt.Printf("  Size: %d bytes\n", info.Size())
		fmt.Printf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
	}

	return nil
}

// runIconInfo implements the icon info command
func runIconInfo(logger interface{}) error {
	iconManager, err := createIconManager(logger)
	if err != nil {
		return err
	}

	fmt.Println("Current Icon Information:")

	currentIcon := iconManager.GetCurrentIcon()
	if currentIcon == "" {
		fmt.Println("✓ Using default application icon")
	} else {
		fmt.Printf("✓ Using custom icon: %s\n", currentIcon)

		if info, err := os.Stat(currentIcon); err == nil {
			fmt.Printf("  Size: %d bytes\n", info.Size())
			fmt.Printf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("  ⚠ Warning: Icon file not accessible: %v\n", err)
		}

		// Check for changes
		changed, err := iconManager.DetectIconChange()
		if err != nil {
			fmt.Printf("  ⚠ Warning: Could not check for changes: %v\n", err)
		} else if changed {
			fmt.Println("  ⚠ Icon file has been modified or removed")
			fmt.Println("    Run 'dirlocker icon detect' to see current status")
		} else {
			fmt.Println("  ✓ Icon file is up to date")
		}
	}

	// Show default icon information
	defaultIcon := iconManager.GetDefaultIcon()
	fmt.Printf("\nDefault Icon: %d bytes embedded\n", len(defaultIcon))

	return nil
}

// runIconApply implements the icon apply command
func runIconApply(iconPath string, logger interface{}) error {
	iconManager, err := createIconManager(logger)
	if err != nil {
		return err
	}

	if iconPath == "" {
		fmt.Println("Applying default icon...")
	} else {
		fmt.Printf("Applying custom icon: %s\n", iconPath)
	}

	if err := iconManager.ApplyIcon(iconPath); err != nil {
		return fmt.Errorf("failed to apply icon: %w", err)
	}

	if iconPath == "" {
		fmt.Println("✓ Default icon applied")
	} else {
		fmt.Println("✓ Custom icon applied")
	}

	fmt.Println("Note: Icon change will take effect on next application restart")

	return nil
}

// createIconManager creates a new icon manager instance
func createIconManager(logger interface{}) (iconmanager.IconManager, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	appDir := filepath.Dir(execPath)
	config := iconmanager.IconManagerConfig{
		AppDir:                appDir,
		EnableChangeDetection: true,
	}

	return iconmanager.NewIconManagerWithCustomLogger(config, logger), nil
}

// scanForAllIcons scans for all .ico files in the directory
func scanForAllIcons(dir string) ([]string, error) {
	var icons []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".ico" {
			icons = append(icons, filepath.Join(dir, entry.Name()))
		}
	}

	return icons, nil
}

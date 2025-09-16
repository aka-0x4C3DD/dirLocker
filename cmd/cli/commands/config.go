package commands

import (
	"fmt"

	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"

	"github.com/spf13/cobra"
)

// NewConfigCommand creates the 'config' command
func NewConfigCommand(cfg *config.Config, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
		Long:  `View and modify application configuration settings.`,
	}

	// Add subcommands
	cmd.AddCommand(newShowConfigCommand(cfg, logger))
	cmd.AddCommand(newSetConfigCommand(cfg, logger))

	return cmd
}

func newShowConfigCommand(cfg *config.Config, _ *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		Long:  `Display the current application configuration settings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Current Configuration:\n\n")
			fmt.Printf("Vault Settings:\n")
			fmt.Printf("  Default Cipher: %s\n", cfg.DefaultCipher)
			fmt.Printf("  Default Chunk Size: %d bytes\n", cfg.DefaultChunkSize)
			fmt.Printf("  Auto Lock Timeout: %s\n", cfg.AutoLockTimeout)
			fmt.Printf("\n")

			fmt.Printf("KDF Parameters:\n")
			fmt.Printf("  Memory: %d KB\n", cfg.KDFParams.Memory)
			fmt.Printf("  Operations: %d\n", cfg.KDFParams.Operations)
			fmt.Printf("  Parallelism: %d\n", cfg.KDFParams.Parallelism)
			fmt.Printf("\n")

			fmt.Printf("Directories:\n")
			fmt.Printf("  Config Dir: %s\n", cfg.ConfigDir)
			fmt.Printf("  Data Dir: %s\n", cfg.DataDir)
			fmt.Printf("  Temp Dir: %s\n", cfg.TempDir)
			fmt.Printf("  Hidden Dir: %s\n", cfg.HiddenDir)
			fmt.Printf("\n")

			fmt.Printf("Logging:\n")
			fmt.Printf("  Level: %s\n", cfg.LogLevel)
			fmt.Printf("  File: %s\n", cfg.GetLogPath())
			fmt.Printf("  Max Size: %d MB\n", cfg.LogMaxSize)
			fmt.Printf("  Max Age: %d days\n", cfg.LogMaxAge)
			fmt.Printf("  Compress: %t\n", cfg.LogCompress)
			fmt.Printf("\n")

			fmt.Printf("Security:\n")
			fmt.Printf("  Secure Memory: %t\n", cfg.SecureMemory)
			fmt.Printf("  Clear Clipboard: %t\n", cfg.ClearClipboard)
			fmt.Printf("  Clipboard Timeout: %s\n", cfg.ClipboardTimeout)

			return nil
		},
	}

	return cmd
}

func newSetConfigCommand(_ *config.Config, _ *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set [key] [value]",
		Short: "Set a configuration value",
		Long:  `Set a configuration value. Use 'config show' to see available keys.`,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			value := args[1]

			// This is a simplified implementation
			// In a real scenario, you would parse the value according to the key type
			// and update the configuration accordingly

			fmt.Printf("Configuration update functionality is simplified in this implementation.\n")
			fmt.Printf("Would set: %s = %s\n", key, value)
			fmt.Printf("Use configuration files or environment variables for full configuration management.\n")

			return nil
		},
	}

	return cmd
}

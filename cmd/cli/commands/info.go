package commands

import (
	"fmt"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewInfoCommand creates the 'info' command
func NewInfoCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info [vault-path]",
		Short: "Display information about a vault",
		Long:  `Display detailed information about a vault file including size, creation time, and accessibility.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			info, err := vaultManager.GetVaultInfo(vaultPath)
			if err != nil {
				return fmt.Errorf("failed to get vault info: %w", err)
			}

			fmt.Printf("Vault Information:\n")
			fmt.Printf("Path: %s\n", info.Path)
			fmt.Printf("Size: %d bytes\n", info.Size)
			fmt.Printf("Modified: %s\n", info.ModifiedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("Accessible: %t\n", info.IsAccessible)

			// Check if vault is currently open
			if _, isOpen := vaultManager.GetVault(vaultPath); isOpen {
				fmt.Printf("Status: Open\n")
			} else {
				fmt.Printf("Status: Closed\n")
			}

			return nil
		},
	}

	return cmd
}
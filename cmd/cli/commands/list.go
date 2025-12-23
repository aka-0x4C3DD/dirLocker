package commands

import (
	"fmt"
	"time"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewListCommand creates the 'list' command
func NewListCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all open vaults",
		Long:  `List all currently open vault containers with their status information.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			openVaults := vaultManager.ListOpenVaults()

			if len(openVaults) == 0 {
				fmt.Println("No vaults are currently open")
				return nil
			}

			fmt.Printf("Open vaults (%d):\n\n", len(openVaults))

			for i, vaultPath := range openVaults {
				managedVault, exists := vaultManager.GetVault(vaultPath)
				if !exists {
					continue // Should not happen, but be safe
				}

				path, openedAt, lastUsed, isShared := managedVault.GetInfo()

				fmt.Printf("%d. %s\n", i+1, path)
				fmt.Printf("   Opened: %s\n", openedAt.Format("2006-01-02 15:04:05"))
				fmt.Printf("   Last used: %s (%s ago)\n",
					lastUsed.Format("2006-01-02 15:04:05"),
					time.Since(lastUsed).Round(time.Second))

				if isShared {
					fmt.Printf("   Type: Shared vault\n")
				} else {
					fmt.Printf("   Type: Personal vault\n")
				}

				if i < len(openVaults)-1 {
					fmt.Println()
				}
			}

			return nil
		},
	}

	return cmd
}

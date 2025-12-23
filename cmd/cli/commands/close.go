package commands

import (
	"fmt"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewCloseCommand creates the 'close' command
func NewCloseCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var closeAll bool

	cmd := &cobra.Command{
		Use:   "close [vault-path]",
		Short: "Close an open vault",
		Long: `Close an open vault container and free its resources.
Use --all flag to close all open vaults.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if closeAll && len(args) > 0 {
				return fmt.Errorf("cannot specify vault path when using --all flag")
			}
			if !closeAll && len(args) != 1 {
				return fmt.Errorf("requires exactly one vault path argument when not using --all")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if closeAll {
				// Close all vaults
				logger.Info("Closing all open vaults")

				openVaults := vaultManager.ListOpenVaults()
				if len(openVaults) == 0 {
					fmt.Println("No vaults are currently open")
					return nil
				}

				if err := vaultManager.CloseAllVaults(); err != nil {
					return fmt.Errorf("failed to close all vaults: %w", err)
				}

				fmt.Printf("Successfully closed %d vault(s)\n", len(openVaults))
				return nil
			}

			// Close specific vault
			vaultPath := args[0]
			logger.Info("Closing vault", "path", vaultPath)

			if err := vaultManager.CloseVault(vaultPath); err != nil {
				return fmt.Errorf("failed to close vault: %w", err)
			}

			fmt.Printf("Successfully closed vault: %s\n", vaultPath)
			return nil
		},
	}

	cmd.Flags().BoolVar(&closeAll, "all", false, "close all open vaults")

	return cmd
}

package commands

import (
	"fmt"
	"syscall"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// NewOpenCommand creates the 'open' command
func NewOpenCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open [vault-path]",
		Short: "Open an encrypted vault",
		Long: `Open an existing encrypted vault container.
The vault will remain open until explicitly closed or the application exits.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Get password from user
			fmt.Print("Enter password for vault: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			fmt.Println()

			password := string(passwordBytes)
			if len(password) == 0 {
				return fmt.Errorf("password cannot be empty")
			}

			// Open the vault
			logger.Info("Opening vault", "path", vaultPath)
			
			managedVault, err := vaultManager.OpenVault(vaultPath, password)
			if err != nil {
				return fmt.Errorf("failed to open vault: %w", err)
			}

			fmt.Printf("Successfully opened vault: %s\n", vaultPath)
			
			// Display vault information
			path, openedAt, _, isShared := managedVault.GetInfo()
			fmt.Printf("Path: %s\n", path)
			fmt.Printf("Opened at: %s\n", openedAt.Format("2006-01-02 15:04:05"))
			if isShared {
				fmt.Println("Type: Shared vault")
			} else {
				fmt.Println("Type: Personal vault")
			}
			
			return nil
		},
	}

	return cmd
}
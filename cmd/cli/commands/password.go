package commands

import (
	"fmt"
	"syscall"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// NewPasswordCommand creates the 'password' command
func NewPasswordCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "password [vault-path]",
		Short: "Change vault password",
		Long:  `Change the password for an existing vault without re-encrypting the content.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Get current password
			fmt.Print("Enter current password: ")
			oldPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read current password: %w", err)
			}
			fmt.Println()

			oldPassword := string(oldPasswordBytes)
			if len(oldPassword) == 0 {
				return fmt.Errorf("current password cannot be empty")
			}

			// Get new password
			fmt.Print("Enter new password: ")
			newPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read new password: %w", err)
			}
			fmt.Println()

			newPassword := string(newPasswordBytes)
			if len(newPassword) == 0 {
				return fmt.Errorf("new password cannot be empty")
			}

			// Confirm new password
			fmt.Print("Confirm new password: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read password confirmation: %w", err)
			}
			fmt.Println()

			if string(confirmBytes) != newPassword {
				return fmt.Errorf("new passwords do not match")
			}

			// Change password
			logger.Info("Changing vault password", "path", vaultPath)

			if err := vaultManager.ChangeVaultPassword(vaultPath, oldPassword, newPassword); err != nil {
				return fmt.Errorf("failed to change password: %w", err)
			}

			fmt.Printf("Successfully changed password for vault: %s\n", vaultPath)
			return nil
		},
	}

	return cmd
}

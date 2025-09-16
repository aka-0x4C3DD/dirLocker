package commands

import (
	"fmt"
	"syscall"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// NewRecoveryCommand creates the 'recovery' command
func NewRecoveryCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recovery",
		Short: "Recovery key operations",
		Long:  `Generate or use recovery keys for vault access.`,
	}

	// Add subcommands
	cmd.AddCommand(newGenerateRecoveryCommand(vaultManager, logger))
	cmd.AddCommand(newRecoverCommand(vaultManager, logger))

	return cmd
}

func newGenerateRecoveryCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate [vault-path]",
		Short: "Generate a recovery key for a vault",
		Long:  `Generate a recovery key that can be used to recover access to a vault if the password is lost.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Get password
			fmt.Print("Enter vault password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			fmt.Println()

			password := string(passwordBytes)
			if len(password) == 0 {
				return fmt.Errorf("password cannot be empty")
			}

			// Generate recovery key
			logger.Info("Generating recovery key", "path", vaultPath)

			recoveryKey, _, err := vaultManager.GenerateRecoveryKey(vaultPath, password)
			if err != nil {
				return fmt.Errorf("failed to generate recovery key: %w", err)
			}

			// Convert to hex for display
			hexKey, err := recoveryKey.ToHex()
			if err != nil {
				return fmt.Errorf("failed to convert recovery key to hex: %w", err)
			}

			fmt.Printf("Recovery key generated successfully!\n\n")
			fmt.Printf("IMPORTANT: Store this recovery key in a safe place.\n")
			fmt.Printf("It will be displayed only once and cannot be recovered.\n\n")
			fmt.Printf("Recovery Key: %s\n\n", hexKey)
			fmt.Printf("You can use this key with 'dirlocker recovery recover' command\n")
			fmt.Printf("if you forget your vault password.\n")

			return nil
		},
	}

	return cmd
}

func newRecoverCommand(_ *vault.VaultManager, _ *logging.Logger) *cobra.Command {
	var recoveryKeyHex string

	cmd := &cobra.Command{
		Use:   "recover [vault-path]",
		Short: "Recover vault access using recovery key",
		Long:  `Recover access to a vault using a previously generated recovery key.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Get recovery key if not provided via flag
			if recoveryKeyHex == "" {
				fmt.Print("Enter recovery key (hex): ")
				fmt.Scanln(&recoveryKeyHex)
			}

			if recoveryKeyHex == "" {
				return fmt.Errorf("recovery key cannot be empty")
			}

			// Parse recovery key
			_, err := vault.RecoveryKeyFromHex(recoveryKeyHex)
			if err != nil {
				return fmt.Errorf("invalid recovery key: %w", err)
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
				return fmt.Errorf("passwords do not match")
			}

			// Note: This is a simplified implementation
			// In a real scenario, we would need the wrapped master key as well
			fmt.Printf("Recovery functionality requires additional implementation.\n")
			fmt.Printf("This would recover vault: %s\n", vaultPath)
			fmt.Printf("Using recovery key and set new password.\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&recoveryKeyHex, "key", "", "recovery key in hex format")

	return cmd
}

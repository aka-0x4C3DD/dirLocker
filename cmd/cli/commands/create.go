package commands

import (
	"fmt"
	"syscall"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// NewCreateCommand creates the 'create' command
func NewCreateCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var (
		cipher     string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "create [vault-name]",
		Short: "Create a new encrypted vault",
		Long: `Create a new encrypted vault container with the specified name.
The vault will be encrypted using the chosen cipher algorithm.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultName := args[0]
			
			// Determine output path
			if outputPath == "" {
				outputPath = vaultName
				if !hasVaultExtension(outputPath) {
					outputPath += ".vault"
				}
			}

			// Validate cipher
			var cipherType vault.CipherType
			switch cipher {
			case "aes-256-gcm", "aes":
				cipherType = vault.CipherAES256GCM
			case "xchacha20poly1305", "xchacha20", "chacha20":
				cipherType = vault.CipherXChaCha20Poly1305
			default:
				return fmt.Errorf("unsupported cipher: %s (supported: aes-256-gcm, xchacha20poly1305)", cipher)
			}

			// Get password from user
			fmt.Print("Enter password for new vault: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			fmt.Println()

			password := string(passwordBytes)
			if len(password) == 0 {
				return fmt.Errorf("password cannot be empty")
			}

			// Confirm password
			fmt.Print("Confirm password: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read password confirmation: %w", err)
			}
			fmt.Println()

			if string(confirmBytes) != password {
				return fmt.Errorf("passwords do not match")
			}

			// Create the vault
			logger.Info("Creating vault", "name", vaultName, "path", outputPath, "cipher", cipher)
			
			if err := vaultManager.CreateVault(outputPath, password, cipherType); err != nil {
				return fmt.Errorf("failed to create vault: %w", err)
			}

			fmt.Printf("Successfully created vault: %s\n", outputPath)
			fmt.Printf("Cipher: %s\n", cipher)
			
			return nil
		},
	}

	cmd.Flags().StringVarP(&cipher, "cipher", "c", "xchacha20poly1305", "encryption cipher (aes-256-gcm, xchacha20poly1305)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "output path for vault file")

	return cmd
}

func hasVaultExtension(path string) bool {
	return len(path) > 6 && (path[len(path)-6:] == ".vault" || path[len(path)-3:] == ".vc")
}
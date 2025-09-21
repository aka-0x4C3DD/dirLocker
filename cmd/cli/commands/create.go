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
		cipher      string
		outputPath  string
		memory      uint32
		operations  uint32
		parallelism uint32
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

			// Create KDF parameters if specified
			var kdfParams *vault.KDFParams
			if memory > 0 || operations > 0 || parallelism > 0 {
				kdfParams = &vault.KDFParams{
					Memory:      memory,
					Operations:  operations,
					Parallelism: parallelism,
				}
			}

			// Create the vault
			logger.Info("Creating vault", "name", vaultName, "path", outputPath, "cipher", cipher)
			
			if err := vaultManager.CreateVaultWithParams(outputPath, password, cipherType, kdfParams); err != nil {
				return fmt.Errorf("failed to create vault: %w", err)
			}

			fmt.Printf("Successfully created vault: %s\n", outputPath)
			fmt.Printf("Cipher: %s\n", cipher)
			
			return nil
		},
	}

	cmd.Flags().StringVarP(&cipher, "cipher", "c", "xchacha20poly1305", "encryption cipher (aes-256-gcm, xchacha20poly1305)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "output path for vault file")
	cmd.Flags().Uint32Var(&memory, "memory", 0, "Argon2id memory parameter in KB (default: 65536)")
	cmd.Flags().Uint32Var(&operations, "operations", 0, "Argon2id operations parameter (default: 3)")
	cmd.Flags().Uint32Var(&parallelism, "parallelism", 0, "Argon2id parallelism parameter (default: 1)")

	return cmd
}

func hasVaultExtension(path string) bool {
	return len(path) > 6 && (path[len(path)-6:] == ".vault" || path[len(path)-3:] == ".vc")
}
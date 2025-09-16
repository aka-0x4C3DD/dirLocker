package commands

import (
	"fmt"
	"os"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewShareCommand creates the 'share' command
func NewShareCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Vault sharing operations",
		Long:  `Manage secure sharing of vaults with other users.`,
	}

	// Add subcommands
	cmd.AddCommand(newGenerateKeyPairCommand(vaultManager, logger))
	cmd.AddCommand(newAddRecipientCommand(vaultManager, logger))
	cmd.AddCommand(newRemoveRecipientCommand(vaultManager, logger))
	cmd.AddCommand(newExportEnvelopesCommand(vaultManager, logger))

	return cmd
}

func newGenerateKeyPairCommand(_ *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new sharing key pair",
		Long:  `Generate a new X25519 key pair for secure vault sharing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Generating sharing key pair")

			keyPair, err := vault.GenerateSharingKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate key pair: %w", err)
			}

			fmt.Printf("Sharing key pair generated successfully!\n\n")
			fmt.Printf("Public Key (share with others):  %x\n", keyPair.PublicKey)
			fmt.Printf("Private Key (keep secret):       %x\n", keyPair.PrivateKey)
			fmt.Printf("\nIMPORTANT: Keep your private key secure and never share it.\n")
			fmt.Printf("Share only your public key with people you want to grant vault access.\n")

			return nil
		},
	}

	return cmd
}

func newAddRecipientCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var publicKeyHex string

	cmd := &cobra.Command{
		Use:   "add [vault-path]",
		Short: "Add a recipient to a vault",
		Long:  `Add a recipient's public key to allow them access to the vault.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			if publicKeyHex == "" {
				fmt.Print("Enter recipient's public key (hex): ")
				fmt.Scanln(&publicKeyHex)
			}

			if len(publicKeyHex) != 64 {
				return fmt.Errorf("public key must be 64 hex characters (32 bytes)")
			}

			// Parse public key
			var publicKey [32]byte
			for i := 0; i < 32; i++ {
				if _, err := fmt.Sscanf(publicKeyHex[i*2:i*2+2], "%02x", &publicKey[i]); err != nil {
					return fmt.Errorf("invalid public key format: %w", err)
				}
			}

			// Get vault
			managedVault, exists := vaultManager.GetVault(vaultPath)
			if !exists {
				return fmt.Errorf("vault is not open: %s", vaultPath)
			}

			// Add recipient
			logger.Info("Adding sharing recipient", "path", vaultPath)

			if err := managedVault.Handle.AddSharingRecipient(publicKey); err != nil {
				return fmt.Errorf("failed to add recipient: %w", err)
			}

			fmt.Printf("Successfully added recipient to vault: %s\n", vaultPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&publicKeyHex, "key", "", "recipient's public key in hex format")

	return cmd
}

func newRemoveRecipientCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var publicKeyHex string

	cmd := &cobra.Command{
		Use:   "remove [vault-path]",
		Short: "Remove a recipient from a vault",
		Long:  `Remove a recipient's access to the vault.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			if publicKeyHex == "" {
				fmt.Print("Enter recipient's public key (hex): ")
				fmt.Scanln(&publicKeyHex)
			}

			if len(publicKeyHex) != 64 {
				return fmt.Errorf("public key must be 64 hex characters (32 bytes)")
			}

			// Parse public key
			var publicKey [32]byte
			for i := 0; i < 32; i++ {
				if _, err := fmt.Sscanf(publicKeyHex[i*2:i*2+2], "%02x", &publicKey[i]); err != nil {
					return fmt.Errorf("invalid public key format: %w", err)
				}
			}

			// Get vault
			managedVault, exists := vaultManager.GetVault(vaultPath)
			if !exists {
				return fmt.Errorf("vault is not open: %s", vaultPath)
			}

			// Remove recipient
			logger.Info("Removing sharing recipient", "path", vaultPath)

			removed, err := managedVault.Handle.RemoveSharingRecipient(publicKey)
			if err != nil {
				return fmt.Errorf("failed to remove recipient: %w", err)
			}

			if removed {
				fmt.Printf("Successfully removed recipient from vault: %s\n", vaultPath)
			} else {
				fmt.Printf("Recipient was not found in vault: %s\n", vaultPath)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&publicKeyHex, "key", "", "recipient's public key in hex format")

	return cmd
}

func newExportEnvelopesCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "export [vault-path]",
		Short: "Export sharing envelopes",
		Long:  `Export sharing envelopes that recipients can use to access the vault.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Get vault
			managedVault, exists := vaultManager.GetVault(vaultPath)
			if !exists {
				return fmt.Errorf("vault is not open: %s", vaultPath)
			}

			// Export envelopes
			logger.Info("Exporting sharing envelopes", "path", vaultPath)

			envelopesJSON, err := managedVault.Handle.ExportSharingEnvelopes()
			if err != nil {
				return fmt.Errorf("failed to export envelopes: %w", err)
			}

			if outputFile != "" {
				// Write to file
				if err := writeToFile(outputFile, envelopesJSON); err != nil {
					return fmt.Errorf("failed to write envelopes to file: %w", err)
				}
				fmt.Printf("Sharing envelopes exported to: %s\n", outputFile)
			} else {
				// Print to stdout
				fmt.Printf("Sharing envelopes:\n%s\n", envelopesJSON)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for envelopes")

	return cmd
}

func writeToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

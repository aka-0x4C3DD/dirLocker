package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewExtractCommand creates the 'extract' command
func NewExtractCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var (
		outputDir   string
		extractAll  bool
		preserveDir bool
	)

	cmd := &cobra.Command{
		Use:   "extract [vault-path] [file-path...]",
		Short: "Extract files from a vault",
		Long: `Extract specific files or all files from an open vault to the local filesystem.
The vault must be open before extracting files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]
			var filePaths []string

			if extractAll {
				if len(args) > 1 {
					return fmt.Errorf("cannot specify file paths when using --all flag")
				}
			} else {
				if len(args) < 2 {
					return fmt.Errorf("must specify file paths to extract or use --all flag")
				}
				filePaths = args[1:]
			}

			// Get vault
			managedVault, exists := vaultManager.GetVault(vaultPath)
			if !exists {
				return fmt.Errorf("vault is not open: %s (use 'dirlocker open' first)", vaultPath)
			}

			// Set default output directory
			if outputDir == "" {
				outputDir = "."
			}

			// Ensure output directory exists
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			logger.Info("Extracting files from vault", "vault", vaultPath, "output", outputDir)

			if extractAll {
				// Extract all files
				fmt.Printf("Extracting all files from vault: %s\n", vaultPath)
				fmt.Printf("Output directory: %s\n", outputDir)
				
				// This is a placeholder for the actual extraction implementation
				// which will use the vault handle to list and extract files
				fmt.Printf("Extract all functionality will be implemented when file operations are available.\n")
				fmt.Printf("This would extract all files from the vault to the output directory.\n")
			} else {
				// Extract specific files
				fmt.Printf("Extracting %d file(s) from vault: %s\n", len(filePaths), vaultPath)
				fmt.Printf("Output directory: %s\n", outputDir)
				
				for _, filePath := range filePaths {
					outputPath := filepath.Join(outputDir, filePath)
					if !preserveDir {
						outputPath = filepath.Join(outputDir, filepath.Base(filePath))
					}
					
					fmt.Printf("  %s -> %s\n", filePath, outputPath)
					
					// This is a placeholder for the actual extraction implementation
					// which will use the vault handle to read and extract the file
					logger.Info("Would extract file", "source", filePath, "dest", outputPath)
				}
				
				fmt.Printf("File extraction functionality will be implemented when file operations are available.\n")
			}

			managedVault.UpdateLastUsed()
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "output directory for extracted files")
	cmd.Flags().BoolVar(&extractAll, "all", false, "extract all files from the vault")
	cmd.Flags().BoolVar(&preserveDir, "preserve-dir", false, "preserve directory structure when extracting")

	return cmd
}
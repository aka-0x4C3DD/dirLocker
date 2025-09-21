package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// NewPushCommand creates the 'push' command
func NewPushCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var (
		recursive   bool
		preserveDir bool
		vaultPath   string
	)

	cmd := &cobra.Command{
		Use:   "push [vault-path] [file-path...]",
		Short: "Add files to a vault",
		Long: `Add files or directories to an open vault.
The vault must be open before adding files.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath = args[0]
			filePaths := args[1:]

			// Get vault
			managedVault, exists := vaultManager.GetVault(vaultPath)
			if !exists {
				return fmt.Errorf("vault is not open: %s (use 'dirlocker open' first)", vaultPath)
			}

			logger.Info("Adding files to vault", "vault", vaultPath, "files", len(filePaths))

			fmt.Printf("Adding %d file(s) to vault: %s\n", len(filePaths), vaultPath)

			for _, filePath := range filePaths {
				// Check if file/directory exists
				stat, err := os.Stat(filePath)
				if err != nil {
					logger.Error("File not found", "path", filePath, "error", err)
					fmt.Printf("  ERROR: %s - file not found\n", filePath)
					continue
				}

				if stat.IsDir() {
					if recursive {
						fmt.Printf("  %s/ (directory - recursive)\n", filePath)
						if err := addDirectoryToVault(managedVault, filePath, preserveDir, logger); err != nil {
							logger.Error("Failed to add directory", "path", filePath, "error", err)
							fmt.Printf("    ERROR: failed to add directory: %v\n", err)
						}
					} else {
						fmt.Printf("  %s/ (directory - skipped, use --recursive)\n", filePath)
					}
				} else {
					fmt.Printf("  %s (%d bytes)\n", filePath, stat.Size())
					if err := addFileToVault(managedVault, filePath, preserveDir, logger); err != nil {
						logger.Error("Failed to add file", "path", filePath, "error", err)
						fmt.Printf("    ERROR: failed to add file: %v\n", err)
					}
				}
			}

			managedVault.UpdateLastUsed()
			fmt.Printf("File push functionality will be implemented when file operations are available.\n")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "recursively add directories")
	cmd.Flags().BoolVar(&preserveDir, "preserve-dir", false, "preserve directory structure in vault")

	return cmd
}

func addFileToVault(managedVault *vault.ManagedVault, filePath string, preserveDir bool, logger *logging.Logger) error {
	// This is a placeholder for the actual file addition implementation
	// which will use the vault handle to write the file content
	
	vaultFilePath := filePath
	if !preserveDir {
		vaultFilePath = filepath.Base(filePath)
	}
	
	logger.Info("Would add file to vault", "source", filePath, "vault_path", vaultFilePath)
	return nil
}

func addDirectoryToVault(managedVault *vault.ManagedVault, dirPath string, preserveDir bool, logger *logging.Logger) error {
	// This is a placeholder for the actual directory addition implementation
	// which will recursively walk the directory and add all files
	
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() {
			vaultFilePath := path
			if !preserveDir {
				relPath, err := filepath.Rel(dirPath, path)
				if err != nil {
					return err
				}
				vaultFilePath = relPath
			}
			
			logger.Info("Would add file to vault", "source", path, "vault_path", vaultFilePath)
		}
		
		return nil
	})
}
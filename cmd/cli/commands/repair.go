package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"dirLocker/pkg/logging"
	"dirLocker/pkg/vault"

	"github.com/spf13/cobra"
)

// VaultIssue represents a vault issue that can be repaired
type VaultIssue struct {
	Description string
	Severity    string
	Fixable     bool
}

// IntegrityResult represents the result of an integrity check
type IntegrityResult struct {
	Status   string
	Issues   []string
	Warnings []string
}

// NewRepairCommand creates the 'repair' command
func NewRepairCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repair",
		Short: "Vault repair and integrity operations",
		Long:  `Repair corrupted vaults and perform integrity checks.`,
	}

	// Add subcommands
	cmd.AddCommand(newRepairVaultCommand(vaultManager, logger))
	cmd.AddCommand(newCheckIntegrityCommand(vaultManager, logger))
	cmd.AddCommand(newVerifyCommand(vaultManager, logger))

	return cmd
}

func newRepairVaultCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var (
		backupPath string
		force      bool
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "vault [vault-path]",
		Short: "Repair a corrupted vault",
		Long:  `Attempt to repair a corrupted vault file by checking integrity and fixing recoverable issues.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Verify vault file exists
			if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
				return fmt.Errorf("vault file does not exist: %s", vaultPath)
			}

			logger.Info("Starting vault repair", "path", vaultPath, "dry_run", dryRun)

			// Create backup if requested
			if backupPath != "" {
				logger.Info("Creating backup", "backup_path", backupPath)
				if err := createBackup(vaultPath, backupPath); err != nil {
					return fmt.Errorf("failed to create backup: %w", err)
				}
				fmt.Printf("Backup created: %s\n", backupPath)
			}

			fmt.Printf("Analyzing vault: %s\n", vaultPath)
			fmt.Printf("Repair mode: %s\n", map[bool]string{true: "dry-run", false: "active"}[dryRun])

			// Perform repair analysis
			issues := analyzeVaultIssues(vaultPath, logger)
			if len(issues) == 0 {
				fmt.Printf("✓ No issues detected in vault\n")
				return nil
			}

			fmt.Printf("\nDetected issues:\n")
			for i, issue := range issues {
				fmt.Printf("%d. %s (severity: %s)\n", i+1, issue.Description, issue.Severity)
			}

			if dryRun {
				fmt.Printf("\nDry run complete. Use --force to apply repairs.\n")
				return nil
			}

			if !force {
				fmt.Printf("\nUse --force to apply repairs or --dry-run to preview changes.\n")
				return nil
			}

			// Apply repairs
			fmt.Printf("\nApplying repairs...\n")
			for i, issue := range issues {
				fmt.Printf("Fixing issue %d/%d: %s\n", i+1, len(issues), issue.Description)
				if err := applyRepair(vaultPath, issue, logger); err != nil {
					logger.Error("Failed to apply repair", "issue", issue.Description, "error", err)
					fmt.Printf("  ✗ Failed: %v\n", err)
				} else {
					fmt.Printf("  ✓ Fixed\n")
				}
			}

			fmt.Printf("\nRepair completed. Run 'dirlocker repair check %s' to verify.\n", vaultPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&backupPath, "backup", "", "create backup before repair")
	cmd.Flags().BoolVar(&force, "force", false, "apply repairs without confirmation")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "analyze issues without applying fixes")

	return cmd
}

func newCheckIntegrityCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	var (
		verbose bool
		quick   bool
	)

	cmd := &cobra.Command{
		Use:   "check [vault-path]",
		Short: "Check vault integrity",
		Long:  `Perform comprehensive integrity checks on a vault without making changes.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Verify vault file exists
			if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
				return fmt.Errorf("vault file does not exist: %s", vaultPath)
			}

			logger.Info("Starting integrity check", "path", vaultPath, "quick", quick)

			fmt.Printf("Checking vault integrity: %s\n", vaultPath)
			fmt.Printf("Check mode: %s\n", map[bool]string{true: "quick", false: "comprehensive"}[quick])

			// Perform integrity checks
			result := performIntegrityCheck(vaultPath, quick, verbose, logger)

			fmt.Printf("\nIntegrity Check Results:\n")
			fmt.Printf("Status: %s\n", result.Status)
			fmt.Printf("Issues found: %d\n", len(result.Issues))
			fmt.Printf("Warnings: %d\n", len(result.Warnings))

			if verbose && len(result.Issues) > 0 {
				fmt.Printf("\nIssues:\n")
				for i, issue := range result.Issues {
					fmt.Printf("%d. %s\n", i+1, issue)
				}
			}

			if verbose && len(result.Warnings) > 0 {
				fmt.Printf("\nWarnings:\n")
				for i, warning := range result.Warnings {
					fmt.Printf("%d. %s\n", i+1, warning)
				}
			}

			if result.Status != "OK" {
				fmt.Printf("\nRun 'dirlocker repair vault %s' to attempt repairs.\n", vaultPath)
				return fmt.Errorf("integrity check failed")
			}

			fmt.Printf("\n✓ Vault integrity check passed\n")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show detailed check results")
	cmd.Flags().BoolVar(&quick, "quick", false, "perform quick check (headers and metadata only)")

	return cmd
}

func newVerifyCommand(vaultManager *vault.VaultManager, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [vault-path]",
		Short: "Verify vault can be opened",
		Long:  `Verify that a vault can be successfully opened and basic operations work.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath := args[0]

			// Verify vault file exists
			if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
				return fmt.Errorf("vault file does not exist: %s", vaultPath)
			}

			logger.Info("Verifying vault", "path", vaultPath)

			fmt.Printf("Verifying vault: %s\n", vaultPath)

			// Get vault info without opening
			info, err := vaultManager.GetVaultInfo(vaultPath)
			if err != nil {
				return fmt.Errorf("failed to get vault info: %w", err)
			}

			fmt.Printf("✓ Vault file accessible\n")
			fmt.Printf("  Size: %d bytes\n", info.Size)
			fmt.Printf("  Modified: %s\n", info.ModifiedAt.Format("2006-01-02 15:04:05"))

			// Note: Full verification would require password input
			// This is a basic file-level verification
			fmt.Printf("\n✓ Basic vault verification passed\n")
			fmt.Printf("Note: Full verification requires opening the vault with a password.\n")

			return nil
		},
	}

	return cmd
}

// Helper functions for repair operations

func createBackup(vaultPath, backupPath string) error {
	// Ensure backup directory exists
	backupDir := filepath.Dir(backupPath)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Copy vault file to backup location
	src, err := os.Open(vaultPath)
	if err != nil {
		return fmt.Errorf("failed to open source vault: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer dst.Close()

	// Copy file contents
	buf := make([]byte, 64*1024) // 64KB buffer
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("failed to write backup: %w", writeErr)
			}
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return fmt.Errorf("failed to read source: %w", err)
		}
	}

	return nil
}

func analyzeVaultIssues(vaultPath string, logger *logging.Logger) []VaultIssue {
	var issues []VaultIssue

	// Check file size
	stat, err := os.Stat(vaultPath)
	if err != nil {
		issues = append(issues, VaultIssue{
			Description: fmt.Sprintf("Cannot access vault file: %v", err),
			Severity:    "critical",
			Fixable:     false,
		})
		return issues
	}

	if stat.Size() == 0 {
		issues = append(issues, VaultIssue{
			Description: "Vault file is empty",
			Severity:    "critical",
			Fixable:     false,
		})
	}

	if stat.Size() < 1024 {
		issues = append(issues, VaultIssue{
			Description: "Vault file is suspiciously small",
			Severity:    "warning",
			Fixable:     false,
		})
	}

	// Check file header (basic validation)
	file, err := os.Open(vaultPath)
	if err != nil {
		issues = append(issues, VaultIssue{
			Description: fmt.Sprintf("Cannot open vault file: %v", err),
			Severity:    "critical",
			Fixable:     false,
		})
		return issues
	}
	defer file.Close()

	header := make([]byte, 16)
	n, err := file.Read(header)
	if err != nil || n < 16 {
		issues = append(issues, VaultIssue{
			Description: "Cannot read vault header",
			Severity:    "critical",
			Fixable:     false,
		})
		return issues
	}

	// Check for vault magic bytes "VLT1"
	if string(header[:4]) != "VLT1" {
		issues = append(issues, VaultIssue{
			Description: "Invalid vault magic bytes - not a valid vault file",
			Severity:    "critical",
			Fixable:     false,
		})
	}

	logger.Debug("Vault analysis complete", "issues_found", len(issues))
	return issues
}

func applyRepair(vaultPath string, issue VaultIssue, logger *logging.Logger) error {
	if !issue.Fixable {
		return fmt.Errorf("issue is not fixable: %s", issue.Description)
	}

	// Placeholder for actual repair implementations
	// In a real implementation, this would contain specific repair logic
	// for different types of issues

	logger.Info("Applied repair", "issue", issue.Description)
	return nil
}

func performIntegrityCheck(vaultPath string, quick, verbose bool, logger *logging.Logger) IntegrityResult {
	result := IntegrityResult{
		Status:   "OK",
		Issues:   []string{},
		Warnings: []string{},
	}

	// Check file accessibility
	stat, err := os.Stat(vaultPath)
	if err != nil {
		result.Status = "ERROR"
		result.Issues = append(result.Issues, fmt.Sprintf("Cannot access vault file: %v", err))
		return result
	}

	// Check file size
	if stat.Size() == 0 {
		result.Status = "ERROR"
		result.Issues = append(result.Issues, "Vault file is empty")
		return result
	}

	if stat.Size() < 1024 {
		result.Warnings = append(result.Warnings, "Vault file is very small")
	}

	// Check file permissions
	mode := stat.Mode()
	if mode.Perm()&0077 != 0 {
		result.Warnings = append(result.Warnings, "Vault file has overly permissive permissions")
	}

	if !quick {
		// Perform comprehensive checks
		file, err := os.Open(vaultPath)
		if err != nil {
			result.Status = "ERROR"
			result.Issues = append(result.Issues, fmt.Sprintf("Cannot open vault file: %v", err))
			return result
		}
		defer file.Close()

		// Check header
		header := make([]byte, 16)
		n, err := file.Read(header)
		if err != nil || n < 16 {
			result.Status = "ERROR"
			result.Issues = append(result.Issues, "Cannot read vault header")
			return result
		}

		// Verify magic bytes
		if string(header[:4]) != "VLT1" {
			result.Status = "ERROR"
			result.Issues = append(result.Issues, "Invalid vault magic bytes")
			return result
		}

		if verbose {
			logger.Debug("Comprehensive integrity check completed", "path", vaultPath)
		}
	}

	if len(result.Issues) > 0 {
		result.Status = "ISSUES_FOUND"
	} else if len(result.Warnings) > 0 {
		result.Status = "WARNINGS"
	}

	return result
}

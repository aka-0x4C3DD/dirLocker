//go:build !windows

package filehider

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// UnixFileHider implements file hiding for Unix-like systems (Linux, macOS) using hidden directories
type UnixFileHider struct {
	hiddenDir string
	registry  *EncryptedRegistry
}

// NewUnixFileHider creates a new Unix file hider instance
func NewUnixFileHider() (FileHider, error) {
	// Use ~/.dirlocker for hidden files
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	hiddenDir := filepath.Join(homeDir, ".dirlocker", "hidden")
	registryPath := filepath.Join(homeDir, ".dirlocker", "registry.enc")

	// Create hidden directory if it doesn't exist
	if err := os.MkdirAll(hiddenDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create hidden directory: %w", err)
	}

	// Use a default password for the registry (in production, this should be derived from user credentials)
	registry := NewEncryptedRegistry(registryPath, "default-registry-password")

	return &UnixFileHider{
		hiddenDir: hiddenDir,
		registry:  registry,
	}, nil
}

// HideFile moves a file to the hidden directory and updates the registry
func (ufh *UnixFileHider) HideFile(path string) error {
	// Get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Check if file exists
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}

	// Load current registry
	registry, err := ufh.registry.Load()
	if err != nil {
		return fmt.Errorf("failed to load registry: %w", err)
	}

	// Check if file is already hidden
	fileName := filepath.Base(absPath)
	if _, exists := registry.Files[fileName]; exists {
		return fmt.Errorf("file %s is already hidden", fileName)
	}

	// Generate unique directory for this file
	fileUUID := uuid.New().String()
	hiddenPath := filepath.Join(ufh.hiddenDir, fileUUID)

	// Create hidden directory for this file
	if err := os.MkdirAll(hiddenPath, 0700); err != nil {
		return fmt.Errorf("failed to create file hidden directory: %w", err)
	}

	// Calculate file checksum for integrity verification
	checksum, err := calculateFileChecksum(absPath)
	if err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// Determine destination path
	destPath := filepath.Join(hiddenPath, fileName)

	// Move file to hidden location
	if fileInfo.IsDir() {
		err = moveDirectory(absPath, destPath)
	} else {
		err = moveFile(absPath, destPath)
	}
	if err != nil {
		return fmt.Errorf("failed to move file to hidden location: %w", err)
	}

	// Set extended attributes if available (for additional metadata)
	if err := setExtendedAttributes(destPath); err != nil {
		// Log warning but don't fail - extended attributes are optional
		fmt.Printf("Warning: failed to set extended attributes on %s: %v\n", destPath, err)
	}

	// Update registry
	registry.Files[fileName] = HiddenFileInfo{
		OriginalPath: absPath,
		HiddenPath:   destPath,
		HiddenAt:     time.Now(),
		FileSize:     fileInfo.Size(),
		Permissions:  fileInfo.Mode(),
		Checksum:     checksum,
	}

	// Save registry
	if err := ufh.registry.Save(registry); err != nil {
		// Try to restore file if registry save fails
		if fileInfo.IsDir() {
			moveDirectory(destPath, absPath)
		} else {
			moveFile(destPath, absPath)
		}
		return fmt.Errorf("failed to save registry: %w", err)
	}

	return nil
}

// UnhideFile restores a hidden file to its original location
func (ufh *UnixFileHider) UnhideFile(name string) error {
	// Load current registry
	registry, err := ufh.registry.Load()
	if err != nil {
		return fmt.Errorf("failed to load registry: %w", err)
	}

	// Find file in registry
	fileInfo, exists := registry.Files[name]
	if !exists {
		return fmt.Errorf("file %s is not hidden", name)
	}

	// Check if hidden file still exists
	if _, err := os.Stat(fileInfo.HiddenPath); err != nil {
		return fmt.Errorf("hidden file not found at %s: %w", fileInfo.HiddenPath, err)
	}

	// Verify file integrity
	currentChecksum, err := calculateFileChecksum(fileInfo.HiddenPath)
	if err != nil {
		return fmt.Errorf("failed to calculate current checksum: %w", err)
	}
	if currentChecksum != fileInfo.Checksum {
		return fmt.Errorf("file integrity check failed - file may have been modified")
	}

	// Check if original location is available
	if _, err := os.Stat(fileInfo.OriginalPath); err == nil {
		return fmt.Errorf("original location %s is occupied", fileInfo.OriginalPath)
	}

	// Ensure original directory exists
	originalDir := filepath.Dir(fileInfo.OriginalPath)
	if err := os.MkdirAll(originalDir, 0755); err != nil {
		return fmt.Errorf("failed to create original directory: %w", err)
	}

	// Move file back to original location
	stat, err := os.Stat(fileInfo.HiddenPath)
	if err != nil {
		return fmt.Errorf("failed to stat hidden file: %w", err)
	}

	if stat.IsDir() {
		err = moveDirectory(fileInfo.HiddenPath, fileInfo.OriginalPath)
	} else {
		err = moveFile(fileInfo.HiddenPath, fileInfo.OriginalPath)
	}
	if err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	// Restore original permissions
	if err := os.Chmod(fileInfo.OriginalPath, fileInfo.Permissions); err != nil {
		// Log warning but don't fail
		fmt.Printf("Warning: failed to restore permissions on %s: %v\n", fileInfo.OriginalPath, err)
	}

	// Remove from registry
	delete(registry.Files, name)

	// Clean up hidden directory
	hiddenDir := filepath.Dir(fileInfo.HiddenPath)
	os.RemoveAll(hiddenDir)

	// Save updated registry
	if err := ufh.registry.Save(registry); err != nil {
		return fmt.Errorf("failed to save registry: %w", err)
	}

	return nil
}

// ListHidden returns all currently hidden files
func (ufh *UnixFileHider) ListHidden() ([]HiddenFileInfo, error) {
	registry, err := ufh.registry.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load registry: %w", err)
	}

	files := make([]HiddenFileInfo, 0, len(registry.Files))
	for _, fileInfo := range registry.Files {
		files = append(files, fileInfo)
	}

	return files, nil
}

// IsHidden checks if a file is currently hidden
func (ufh *UnixFileHider) IsHidden(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	registry, err := ufh.registry.Load()
	if err != nil {
		return false
	}

	fileName := filepath.Base(absPath)
	_, exists := registry.Files[fileName]
	return exists
}

// Helper functions

// setExtendedAttributes sets extended attributes on Unix systems
func setExtendedAttributes(path string) error {
	// This is a placeholder for extended attributes functionality
	// On Linux, you would use the "github.com/pkg/xattr" package
	// On macOS, you would use similar extended attributes APIs
	// For now, we'll just return nil as extended attributes are optional
	return nil
}

// moveFile moves a file from source to destination
func moveFile(src, dst string) error {
	// Try rename first (fastest if on same volume)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// Fall back to copy and delete
	if err := copyFile(src, dst); err != nil {
		return err
	}

	return os.Remove(src)
}

// moveDirectory moves a directory from source to destination
func moveDirectory(src, dst string) error {
	// Try rename first (fastest if on same volume)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// Fall back to recursive copy and delete
	if err := copyDirectory(src, dst); err != nil {
		return err
	}

	return os.RemoveAll(src)
}

// copyFile copies a single file
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// Copy file permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}

// copyDirectory recursively copies a directory
func copyDirectory(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate destination path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		return copyFile(path, dstPath)
	})
}

// calculateFileChecksum calculates SHA256 checksum of a file or directory
func calculateFileChecksum(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()

	if info.IsDir() {
		// For directories, hash the directory structure and file contents
		err := filepath.Walk(path, func(filePath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Include relative path in hash
			relPath, err := filepath.Rel(path, filePath)
			if err != nil {
				return err
			}
			hasher.Write([]byte(relPath))

			if !fileInfo.IsDir() {
				file, err := os.Open(filePath)
				if err != nil {
					return err
				}
				defer file.Close()

				if _, err := io.Copy(hasher, file); err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return "", err
		}
	} else {
		// For files, hash the file content
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer file.Close()

		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

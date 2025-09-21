package iconmanager

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultIconManager implements the IconManager interface
type DefaultIconManager struct {
	appDir          string
	currentIcon     string
	defaultIcon     []byte
	lastIconModTime time.Time
	logger          *logrus.Logger
}

// NewIconManager creates a new icon manager instance
func NewIconManager(config IconManagerConfig, logger *logrus.Logger) *DefaultIconManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &DefaultIconManager{
		appDir:      config.AppDir,
		defaultIcon: getEmbeddedDefaultIcon(),
		logger:      logger,
	}
}

// NewIconManagerWithCustomLogger creates a new icon manager instance with a custom logger interface
func NewIconManagerWithCustomLogger(config IconManagerConfig, customLogger interface{}) *DefaultIconManager {
	var logger *logrus.Logger

	// Try to extract logrus.Logger from custom logger types
	switch l := customLogger.(type) {
	case *logrus.Logger:
		logger = l
	case interface{ Logger() *logrus.Logger }:
		// If the custom logger has a Logger() method that returns *logrus.Logger
		logger = l.Logger()
	default:
		// Fallback to creating a new logger
		logger = logrus.New()
	}

	return &DefaultIconManager{
		appDir:      config.AppDir,
		defaultIcon: getEmbeddedDefaultIcon(),
		logger:      logger,
	}
}

// DetectCustomIcon scans the application directory for .ico files
func (im *DefaultIconManager) DetectCustomIcon() (string, error) {
	if im.appDir == "" {
		return "", fmt.Errorf("application directory not set")
	}

	// Scan for .ico files in the application directory
	icoFiles, err := im.scanForIcoFiles()
	if err != nil {
		return "", fmt.Errorf("failed to scan for .ico files: %w", err)
	}

	if len(icoFiles) == 0 {
		im.logger.Debug("No custom .ico files found in application directory")
		return "", nil
	}

	if len(icoFiles) == 1 {
		iconPath := icoFiles[0]
		if err := im.ValidateIcon(iconPath); err != nil {
			im.logger.WithError(err).Errorf("Invalid .ico file found: %s", iconPath)
			return "", nil
		}
		im.logger.Infof("Found valid custom icon: %s", iconPath)
		return iconPath, nil
	}

	// Handle multiple icons
	return im.HandleMultipleIcons(icoFiles)
}

// scanForIcoFiles scans the application directory for .ico files
func (im *DefaultIconManager) scanForIcoFiles() ([]string, error) {
	var icoFiles []string

	err := filepath.Walk(im.appDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only check files in the root application directory, not subdirectories
		if filepath.Dir(path) != im.appDir {
			return nil
		}

		if !info.IsDir() && strings.ToLower(filepath.Ext(path)) == ".ico" {
			icoFiles = append(icoFiles, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return icoFiles, nil
}

// HandleMultipleIcons handles the case where multiple .ico files are found
func (im *DefaultIconManager) HandleMultipleIcons(icons []string) (string, error) {
	if len(icons) == 0 {
		return "", fmt.Errorf("no icons provided")
	}

	// Sort alphabetically to ensure consistent selection
	sort.Strings(icons)

	// Log warning about multiple icons
	im.logger.Warnf("Multiple .ico files found in application directory: %v", icons)
	im.logger.Warnf("Using first icon alphabetically: %s", icons[0])

	// Validate the selected icon
	selectedIcon := icons[0]
	if err := im.ValidateIcon(selectedIcon); err != nil {
		im.logger.WithError(err).Errorf("Selected icon is invalid: %s", selectedIcon)

		// Try other icons in order
		for i := 1; i < len(icons); i++ {
			if err := im.ValidateIcon(icons[i]); err == nil {
				im.logger.Infof("Using alternative valid icon: %s", icons[i])
				return icons[i], nil
			}
		}

		return "", fmt.Errorf("no valid icons found among multiple .ico files")
	}

	return selectedIcon, nil
}

// ValidateIcon validates that an icon file is not corrupted
func (im *DefaultIconManager) ValidateIcon(iconPath string) error {
	if iconPath == "" {
		return fmt.Errorf("icon path is empty")
	}

	// Check if file exists
	info, err := os.Stat(iconPath)
	if err != nil {
		return fmt.Errorf("icon file does not exist: %w", err)
	}

	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return fmt.Errorf("icon path is not a regular file")
	}

	// Check file size (should be reasonable for an icon)
	if info.Size() == 0 {
		return fmt.Errorf("icon file is empty")
	}

	if info.Size() > 10*1024*1024 { // 10MB limit
		return fmt.Errorf("icon file is too large: %d bytes", info.Size())
	}

	// Open and validate basic ICO file structure
	file, err := os.Open(iconPath)
	if err != nil {
		return fmt.Errorf("failed to open icon file: %w", err)
	}
	defer file.Close()

	// Read ICO header (first 6 bytes)
	header := make([]byte, 6)
	if _, err := io.ReadFull(file, header); err != nil {
		return fmt.Errorf("failed to read icon header: %w", err)
	}

	// Validate ICO signature
	// ICO files start with: 00 00 01 00 (reserved, type, count)
	if header[0] != 0x00 || header[1] != 0x00 || header[2] != 0x01 || header[3] != 0x00 {
		return fmt.Errorf("invalid ICO file signature")
	}

	// Check if there's at least one icon entry
	iconCount := uint16(header[4]) | (uint16(header[5]) << 8)
	if iconCount == 0 {
		return fmt.Errorf("ICO file contains no icons")
	}

	im.logger.Debugf("Icon validation successful: %s (%d icons, %d bytes)", iconPath, iconCount, info.Size())
	return nil
}

// ApplyIcon applies the specified icon to the application
func (im *DefaultIconManager) ApplyIcon(iconPath string) error {
	if iconPath == "" {
		// Use default icon
		im.currentIcon = ""
		im.logger.Info("Applied default application icon")
		return nil
	}

	// Validate the icon first
	if err := im.ValidateIcon(iconPath); err != nil {
		im.logger.WithError(err).Errorf("Cannot apply invalid icon: %s", iconPath)
		return fmt.Errorf("icon validation failed: %w", err)
	}

	// Store the current icon path
	im.currentIcon = iconPath

	// Update last modification time
	if info, err := os.Stat(iconPath); err == nil {
		im.lastIconModTime = info.ModTime()
	}

	im.logger.Infof("Applied custom icon: %s", iconPath)

	// Note: Actual icon application to the running application would require
	// platform-specific implementation and might need application restart
	im.logger.Info("Note: Icon change will take effect on next application restart")

	return nil
}

// GetCurrentIcon returns the path to the currently applied icon
func (im *DefaultIconManager) GetCurrentIcon() string {
	return im.currentIcon
}

// GetDefaultIcon returns the embedded default icon data
func (im *DefaultIconManager) GetDefaultIcon() []byte {
	return im.defaultIcon
}

// DetectIconChange checks if the icon file has been modified since last check
func (im *DefaultIconManager) DetectIconChange() (bool, error) {
	if im.currentIcon == "" {
		// No custom icon set, check if one was added
		customIcon, err := im.DetectCustomIcon()
		if err != nil {
			return false, err
		}

		return customIcon != "", nil
	}

	// Check if current icon still exists and hasn't been modified
	info, err := os.Stat(im.currentIcon)
	if err != nil {
		if os.IsNotExist(err) {
			im.logger.Warnf("Current icon file no longer exists: %s", im.currentIcon)
			return true, nil
		}
		return false, fmt.Errorf("failed to check icon file: %w", err)
	}

	// Check if modification time changed
	if !info.ModTime().Equal(im.lastIconModTime) {
		im.logger.Infof("Icon file modification detected: %s", im.currentIcon)
		return true, nil
	}

	return false, nil
}

// GetIconModTime returns the modification time of the current icon
func (im *DefaultIconManager) GetIconModTime(iconPath string) (time.Time, error) {
	if iconPath == "" {
		return time.Time{}, fmt.Errorf("icon path is empty")
	}

	info, err := os.Stat(iconPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get icon file info: %w", err)
	}

	return info.ModTime(), nil
}

// getEmbeddedDefaultIcon returns the embedded default icon data
// This would typically be embedded using go:embed or similar
func getEmbeddedDefaultIcon() []byte {
	// Placeholder for embedded default icon
	// In a real implementation, this would contain the actual default icon bytes
	return []byte{
		// ICO header for a minimal 16x16 icon
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, // ICO signature and count
		0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, // Icon directory entry
		0x68, 0x04, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, // Size and offset
		// Minimal bitmap data would follow...
	}
}

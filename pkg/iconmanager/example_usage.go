package iconmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// ExampleUsage demonstrates how to use the IconManager in an application
func ExampleUsage() {
	// Get the application directory (where the executable is located)
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("Failed to get executable path: %v\n", err)
		return
	}
	appDir := filepath.Dir(execPath)

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create icon manager configuration
	config := IconManagerConfig{
		AppDir:                appDir,
		EnableChangeDetection: true,
	}

	// Create icon manager
	iconManager := NewIconManager(config, logger)

	// Example 1: Detect and apply custom icon on application startup
	fmt.Println("=== Application Startup Icon Detection ===")
	customIcon, err := iconManager.DetectCustomIcon()
	if err != nil {
		logger.WithError(err).Error("Failed to detect custom icon")
	} else if customIcon != "" {
		logger.Infof("Found custom icon: %s", customIcon)
		if err := iconManager.ApplyIcon(customIcon); err != nil {
			logger.WithError(err).Error("Failed to apply custom icon")
		} else {
			logger.Info("Custom icon applied successfully")
		}
	} else {
		logger.Info("No custom icon found, using default")
		if err := iconManager.ApplyIcon(""); err != nil {
			logger.WithError(err).Error("Failed to apply default icon")
		}
	}

	// Example 2: Periodic icon change detection (in a background goroutine)
	fmt.Println("\n=== Periodic Icon Change Detection ===")
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			changed, err := iconManager.DetectIconChange()
			if err != nil {
				logger.WithError(err).Error("Failed to detect icon changes")
				continue
			}

			if changed {
				logger.Info("Icon change detected, updating...")

				// Re-detect the current icon
				newIcon, err := iconManager.DetectCustomIcon()
				if err != nil {
					logger.WithError(err).Error("Failed to detect new icon")
					continue
				}

				// Apply the new icon (or default if none found)
				if err := iconManager.ApplyIcon(newIcon); err != nil {
					logger.WithError(err).Error("Failed to apply new icon")
				} else {
					if newIcon == "" {
						logger.Info("Reverted to default icon")
					} else {
						logger.Infof("Applied new icon: %s", newIcon)
					}
				}
			}
		}
	}()

	// Example 3: Manual icon validation
	fmt.Println("\n=== Manual Icon Validation ===")
	testIconPath := filepath.Join(appDir, "test.ico")
	if err := iconManager.ValidateIcon(testIconPath); err != nil {
		logger.WithError(err).Warnf("Icon validation failed for: %s", testIconPath)
	} else {
		logger.Infof("Icon validation successful for: %s", testIconPath)
	}

	// Example 4: Get current icon information
	fmt.Println("\n=== Current Icon Information ===")
	currentIcon := iconManager.GetCurrentIcon()
	if currentIcon == "" {
		logger.Info("Currently using default icon")
	} else {
		logger.Infof("Currently using custom icon: %s", currentIcon)

		modTime, err := iconManager.GetIconModTime(currentIcon)
		if err != nil {
			logger.WithError(err).Error("Failed to get icon modification time")
		} else {
			logger.Infof("Icon last modified: %s", modTime.Format(time.RFC3339))
		}
	}

	// Example 5: Handle application shutdown
	fmt.Println("\n=== Application Shutdown ===")
	logger.Info("Application shutting down, icon manager cleanup complete")
}

// ApplicationStartupIconSetup demonstrates the recommended way to set up icons during application startup
func ApplicationStartupIconSetup(appDir string, logger *logrus.Logger) (*DefaultIconManager, error) {
	config := IconManagerConfig{
		AppDir:                appDir,
		EnableChangeDetection: true,
	}

	iconManager := NewIconManager(config, logger)

	// Detect and apply custom icon
	customIcon, err := iconManager.DetectCustomIcon()
	if err != nil {
		return nil, fmt.Errorf("failed to detect custom icon: %w", err)
	}

	if err := iconManager.ApplyIcon(customIcon); err != nil {
		return nil, fmt.Errorf("failed to apply icon: %w", err)
	}

	if customIcon == "" {
		logger.Info("Using default application icon")
	} else {
		logger.Infof("Using custom icon: %s", customIcon)
	}

	return iconManager, nil
}

// StartIconChangeMonitoring starts a background goroutine to monitor for icon changes
func StartIconChangeMonitoring(iconManager IconManager, logger *logrus.Logger, stopChan <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			changed, err := iconManager.DetectIconChange()
			if err != nil {
				logger.WithError(err).Error("Failed to detect icon changes")
				continue
			}

			if changed {
				logger.Info("Icon change detected - application restart recommended")

				// Optionally, you could trigger an application restart notification here
				// or update the icon immediately if your application supports it

				// Re-detect and apply the new icon
				if dm, ok := iconManager.(*DefaultIconManager); ok {
					newIcon, err := dm.DetectCustomIcon()
					if err != nil {
						logger.WithError(err).Error("Failed to detect new icon")
						continue
					}

					if err := dm.ApplyIcon(newIcon); err != nil {
						logger.WithError(err).Error("Failed to apply new icon")
					} else {
						if newIcon == "" {
							logger.Info("Reverted to default icon - restart to see changes")
						} else {
							logger.Infof("Applied new icon: %s - restart to see changes", newIcon)
						}
					}
				}
			}

		case <-stopChan:
			logger.Info("Icon change monitoring stopped")
			return
		}
	}
}

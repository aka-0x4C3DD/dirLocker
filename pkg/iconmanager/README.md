# Icon Manager Package

The `iconmanager` package provides functionality for detecting, validating, and managing custom application icons in the dirLocker application.

## Features

- **Automatic Icon Detection**: Scans the application directory for `.ico` files
- **Icon Validation**: Validates ICO file format and structure
- **Multiple Icon Handling**: Handles cases where multiple `.ico` files are present
- **Change Detection**: Monitors for icon file changes
- **Fallback Support**: Falls back to default icon when custom icons are invalid
- **Comprehensive Logging**: Provides detailed logging for debugging and monitoring

## Requirements Satisfied

This package satisfies the following requirements from the specification:

- **13.1**: When a .ico file is placed in the application folder, the system uses it as the application icon
- **13.2**: When multiple .ico files are present, the system uses the first one alphabetically and logs a warning
- **13.3**: When no .ico file is present, the system uses the default built-in application icon
- **13.4**: When the .ico file is invalid or corrupted, the system falls back to the default icon and logs an error
- **13.5**: When the .ico file is updated, the system detects the change and updates the application icon on next restart

## Usage

### Basic Setup

```go
package main

import (
    "os"
    "path/filepath"
    
    "github.com/sirupsen/logrus"
    "your-project/pkg/iconmanager"
)

func main() {
    // Get application directory
    execPath, _ := os.Executable()
    appDir := filepath.Dir(execPath)
    
    // Create configuration
    config := iconmanager.IconManagerConfig{
        AppDir:                appDir,
        EnableChangeDetection: true,
    }
    
    // Create logger
    logger := logrus.New()
    
    // Create icon manager
    manager := iconmanager.NewIconManager(config, logger)
    
    // Detect and apply custom icon
    customIcon, err := manager.DetectCustomIcon()
    if err != nil {
        logger.WithError(err).Error("Failed to detect custom icon")
        return
    }
    
    if err := manager.ApplyIcon(customIcon); err != nil {
        logger.WithError(err).Error("Failed to apply icon")
        return
    }
    
    if customIcon == "" {
        logger.Info("Using default application icon")
    } else {
        logger.Infof("Using custom icon: %s", customIcon)
    }
}
```

### Icon Change Monitoring

```go
// Start background monitoring for icon changes
stopChan := make(chan struct{})
go iconmanager.StartIconChangeMonitoring(manager, logger, stopChan)

// Later, stop monitoring
close(stopChan)
```

### Manual Icon Operations

```go
// Validate a specific icon file
err := manager.ValidateIcon("/path/to/icon.ico")
if err != nil {
    log.Printf("Icon validation failed: %v", err)
}

// Get current icon information
currentIcon := manager.GetCurrentIcon()
if currentIcon != "" {
    modTime, _ := manager.GetIconModTime(currentIcon)
    log.Printf("Current icon: %s (modified: %s)", currentIcon, modTime)
}

// Check for icon changes
changed, err := manager.DetectIconChange()
if err == nil && changed {
    log.Println("Icon change detected!")
}
```

## API Reference

### Types

#### `IconManager` Interface

The main interface for icon management operations.

```go
type IconManager interface {
    DetectCustomIcon() (string, error)
    ApplyIcon(iconPath string) error
    HandleMultipleIcons(icons []string) (string, error)
    ValidateIcon(iconPath string) error
    GetCurrentIcon() string
    GetDefaultIcon() []byte
    DetectIconChange() (bool, error)
    GetIconModTime(iconPath string) (time.Time, error)
}
```

#### `IconManagerConfig`

Configuration structure for the icon manager.

```go
type IconManagerConfig struct {
    AppDir                string `json:"app_dir"`
    DefaultIconPath       string `json:"default_icon_path"`
    EnableChangeDetection bool   `json:"enable_change_detection"`
}
```

#### `IconInfo`

Information about a detected icon file.

```go
type IconInfo struct {
    Path         string    `json:"path"`
    Size         int64     `json:"size"`
    ModTime      time.Time `json:"mod_time"`
    IsValid      bool      `json:"is_valid"`
    ErrorMessage string    `json:"error_message,omitempty"`
}
```

### Methods

#### `NewIconManager(config IconManagerConfig, logger *logrus.Logger) *DefaultIconManager`

Creates a new icon manager instance with the specified configuration and logger.

#### `DetectCustomIcon() (string, error)`

Scans the application directory for `.ico` files and returns the path to the selected icon, or empty string if none found.

#### `ApplyIcon(iconPath string) error`

Applies the specified icon to the application. Pass empty string to use the default icon.

#### `ValidateIcon(iconPath string) error`

Validates that the specified icon file is a valid ICO file and not corrupted.

#### `HandleMultipleIcons(icons []string) (string, error)`

Handles the case where multiple `.ico` files are found, selecting the first one alphabetically.

#### `GetCurrentIcon() string`

Returns the path to the currently applied icon, or empty string if using the default icon.

#### `DetectIconChange() (bool, error)`

Checks if the current icon file has been modified, deleted, or if new icons have been added.

## Icon File Requirements

The icon manager validates ICO files according to the following criteria:

- **File Format**: Must be a valid ICO file with proper signature (00 00 01 00)
- **File Size**: Must be between 1 byte and 10MB
- **Icon Count**: Must contain at least one icon entry
- **File Access**: Must be a readable regular file

## Error Handling

The package provides comprehensive error handling with specific error types:

- **Validation Errors**: Invalid ICO format, corrupted files, size limits
- **File System Errors**: File not found, permission denied, I/O errors
- **Configuration Errors**: Invalid application directory, missing parameters

All errors are logged with appropriate severity levels and include contextual information for debugging.

## Testing

The package includes comprehensive unit tests covering:

- Icon detection scenarios (no icons, single icon, multiple icons)
- Icon validation (valid/invalid ICO files, edge cases)
- Change detection (file modifications, deletions, additions)
- Error handling (missing files, corrupted data, permission issues)
- Integration workflows (complete application startup scenarios)

Run tests with:

```bash
go test ./pkg/iconmanager -v
```

## Platform Compatibility

The icon manager is designed to work across all supported platforms:

- **Windows**: Supports standard ICO files and Windows file attributes
- **macOS**: Compatible with macOS file system and application bundles
- **Linux**: Works with standard Unix file systems and desktop environments

## Security Considerations

- Icon files are validated before use to prevent malicious file exploitation
- File size limits prevent resource exhaustion attacks
- Secure file handling prevents path traversal vulnerabilities
- No sensitive information is logged during icon operations

## Performance

- Icon detection is performed on-demand to minimize startup overhead
- File validation uses minimal memory footprint
- Change detection is optimized for periodic monitoring
- Default icon is embedded to eliminate external dependencies
package iconmanager

import (
	"time"
)

// IconManager provides functionality for detecting and managing custom application icons
type IconManager interface {
	// DetectCustomIcon scans the application directory for .ico files
	DetectCustomIcon() (string, error)

	// ApplyIcon applies the specified icon to the application
	ApplyIcon(iconPath string) error

	// HandleMultipleIcons handles the case where multiple .ico files are found
	HandleMultipleIcons(icons []string) (string, error)

	// ValidateIcon validates that an icon file is not corrupted
	ValidateIcon(iconPath string) error

	// GetCurrentIcon returns the path to the currently applied icon
	GetCurrentIcon() string

	// GetDefaultIcon returns the embedded default icon data
	GetDefaultIcon() []byte

	// DetectIconChange checks if the icon file has been modified since last check
	DetectIconChange() (bool, error)

	// GetIconModTime returns the modification time of the current icon
	GetIconModTime(iconPath string) (time.Time, error)
}

// IconInfo represents information about a detected icon file
type IconInfo struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	IsValid      bool      `json:"is_valid"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// IconManagerConfig holds configuration for the icon manager
type IconManagerConfig struct {
	AppDir                string `json:"app_dir"`
	DefaultIconPath       string `json:"default_icon_path"`
	EnableChangeDetection bool   `json:"enable_change_detection"`
}

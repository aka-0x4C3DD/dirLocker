package filehider

import (
	"os"
	"time"
)

// FileHider defines the interface for hiding and unhiding files from the operating system
type FileHider interface {
	// HideFile makes a file or directory invisible to the operating system
	HideFile(path string) error

	// UnhideFile restores a previously hidden file or directory to normal OS visibility
	UnhideFile(name string) error

	// ListHidden returns a list of all currently hidden files
	ListHidden() ([]HiddenFileInfo, error)

	// IsHidden checks if a file is currently hidden by this system
	IsHidden(path string) bool
}

// HiddenFileInfo contains metadata about a hidden file
type HiddenFileInfo struct {
	OriginalPath string      `json:"original_path"`
	HiddenPath   string      `json:"hidden_path"`
	HiddenAt     time.Time   `json:"hidden_at"`
	FileSize     int64       `json:"file_size"`
	Permissions  os.FileMode `json:"permissions"`
	Checksum     string      `json:"checksum"`
}

// HiddenFileRegistry stores the encrypted registry of hidden files
type HiddenFileRegistry struct {
	Version int                       `json:"version"`
	Files   map[string]HiddenFileInfo `json:"files"`
	Salt    []byte                    `json:"salt"`
}

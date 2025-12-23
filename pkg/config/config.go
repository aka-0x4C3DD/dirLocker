package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	// Vault settings
	DefaultCipher    string        `json:"default_cipher" mapstructure:"default_cipher"`
	DefaultChunkSize int           `json:"default_chunk_size" mapstructure:"default_chunk_size"`
	AutoLockTimeout  time.Duration `json:"auto_lock_timeout" mapstructure:"auto_lock_timeout"`

	// KDF parameters
	KDFParams KDFParams `json:"kdf_params" mapstructure:"kdf_params"`

	// File system settings
	MountPoints map[string]string `json:"mount_points" mapstructure:"mount_points"`
	HiddenDir   string            `json:"hidden_dir" mapstructure:"hidden_dir"`

	// UI settings
	IconPath string `json:"icon_path" mapstructure:"icon_path"`

	// Logging settings
	LogLevel    string `json:"log_level" mapstructure:"log_level"`
	LogFile     string `json:"log_file" mapstructure:"log_file"`
	LogMaxSize  int    `json:"log_max_size" mapstructure:"log_max_size"`
	LogMaxAge   int    `json:"log_max_age" mapstructure:"log_max_age"`
	LogCompress bool   `json:"log_compress" mapstructure:"log_compress"`

	// Security settings
	SecureMemory     bool          `json:"secure_memory" mapstructure:"secure_memory"`
	ClearClipboard   bool          `json:"clear_clipboard" mapstructure:"clear_clipboard"`
	ClipboardTimeout time.Duration `json:"clipboard_timeout" mapstructure:"clipboard_timeout"`

	// Application settings
	ConfigDir   string `json:"config_dir" mapstructure:"config_dir"`
	DataDir     string `json:"data_dir" mapstructure:"data_dir"`
	TempDir     string `json:"temp_dir" mapstructure:"temp_dir"`
	CheckUpdate bool   `json:"check_update" mapstructure:"check_update"`
}

// KDFParams represents key derivation function parameters
type KDFParams struct {
	Memory      uint32 `json:"memory" mapstructure:"memory"`
	Operations  uint32 `json:"operations" mapstructure:"operations"`
	Parallelism uint32 `json:"parallelism" mapstructure:"parallelism"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".dirlocker")

	return &Config{
		// Vault settings
		DefaultCipher:    "xchacha20poly1305",
		DefaultChunkSize: 4 * 1024 * 1024, // 4MB
		AutoLockTimeout:  30 * time.Minute,

		// KDF parameters (secure defaults)
		KDFParams: KDFParams{
			Memory:      64 * 1024, // 64MB
			Operations:  3,
			Parallelism: 1,
		},

		// File system settings
		MountPoints: make(map[string]string),
		HiddenDir:   filepath.Join(configDir, "hidden"),

		// UI settings
		IconPath: "",

		// Logging settings
		LogLevel:    "info",
		LogFile:     filepath.Join(configDir, "dirlocker.log"),
		LogMaxSize:  10, // 10MB
		LogMaxAge:   30, // 30 days
		LogCompress: true,

		// Security settings
		SecureMemory:     true,
		ClearClipboard:   true,
		ClipboardTimeout: 30 * time.Second,

		// Application settings
		ConfigDir:   configDir,
		DataDir:     filepath.Join(configDir, "data"),
		TempDir:     filepath.Join(configDir, "temp"),
		CheckUpdate: true,
	}
}

// LoadConfig loads configuration from file or creates default if not exists
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// If no config path specified, use default
	if configPath == "" {
		configPath = filepath.Join(config.ConfigDir, "config.json")
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config file
		if err := config.SaveToFile(configPath); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		return config, nil
	}

	// Load existing config file
	viper.SetConfigFile(configPath)
	viper.SetConfigType("json")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate and fix config
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// SaveToFile saves the configuration to a JSON file
func (c *Config) SaveToFile(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal config to JSON
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the configuration and sets defaults for invalid values
func (c *Config) Validate() error {
	// Validate cipher
	if c.DefaultCipher != "aes-256-gcm" && c.DefaultCipher != "xchacha20poly1305" {
		c.DefaultCipher = "xchacha20poly1305"
	}

	// Validate chunk size (minimum 1MB, maximum 64MB)
	if c.DefaultChunkSize < 1024*1024 {
		c.DefaultChunkSize = 1024 * 1024 // 1MB
	} else if c.DefaultChunkSize > 64*1024*1024 {
		c.DefaultChunkSize = 64 * 1024 * 1024 // 64MB
	}

	// Validate KDF parameters
	if c.KDFParams.Memory < 32*1024 {
		c.KDFParams.Memory = 64 * 1024 // 64MB minimum
	}
	if c.KDFParams.Operations < 1 {
		c.KDFParams.Operations = 3
	}
	if c.KDFParams.Parallelism < 1 {
		c.KDFParams.Parallelism = 1
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[c.LogLevel] {
		c.LogLevel = "info"
	}

	// Validate log settings
	if c.LogMaxSize <= 0 {
		c.LogMaxSize = 10
	}
	if c.LogMaxAge <= 0 {
		c.LogMaxAge = 30
	}

	// Validate timeout settings
	if c.AutoLockTimeout < 0 {
		c.AutoLockTimeout = 0 // Disable auto-lock
	}
	if c.ClipboardTimeout < 0 {
		c.ClipboardTimeout = 30 * time.Second
	}

	// Ensure directories exist
	dirs := []string{c.ConfigDir, c.DataDir, c.TempDir, c.HiddenDir}
	for _, dir := range dirs {
		if dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
	}

	return nil
}

// GetVaultPath returns the full path for a vault file
func (c *Config) GetVaultPath(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.DataDir, name)
}

// GetTempPath returns a path in the temp directory
func (c *Config) GetTempPath(name string) string {
	return filepath.Join(c.TempDir, name)
}

// GetHiddenPath returns a path in the hidden directory
func (c *Config) GetHiddenPath(name string) string {
	return filepath.Join(c.HiddenDir, name)
}

// GetLogPath returns the log file path
func (c *Config) GetLogPath() string {
	if filepath.IsAbs(c.LogFile) {
		return c.LogFile
	}
	return filepath.Join(c.ConfigDir, c.LogFile)
}

// SetMountPoint sets a mount point for a vault
func (c *Config) SetMountPoint(vaultPath, mountPoint string) {
	if c.MountPoints == nil {
		c.MountPoints = make(map[string]string)
	}
	c.MountPoints[vaultPath] = mountPoint
}

// GetMountPoint gets the mount point for a vault
func (c *Config) GetMountPoint(vaultPath string) (string, bool) {
	if c.MountPoints == nil {
		return "", false
	}
	mountPoint, exists := c.MountPoints[vaultPath]
	return mountPoint, exists
}

// RemoveMountPoint removes a mount point for a vault
func (c *Config) RemoveMountPoint(vaultPath string) {
	if c.MountPoints != nil {
		delete(c.MountPoints, vaultPath)
	}
}

// Clone creates a deep copy of the configuration
func (c *Config) Clone() *Config {
	clone := *c

	// Deep copy mount points map
	if c.MountPoints != nil {
		clone.MountPoints = make(map[string]string)
		for k, v := range c.MountPoints {
			clone.MountPoints[k] = v
		}
	}

	return &clone
}

// String returns a string representation of the config (without sensitive data)
func (c *Config) String() string {
	return fmt.Sprintf("Config{DefaultCipher: %s, ChunkSize: %d, LogLevel: %s, ConfigDir: %s}",
		c.DefaultCipher, c.DefaultChunkSize, c.LogLevel, c.ConfigDir)
}

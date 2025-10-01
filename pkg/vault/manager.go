package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dirLocker/pkg/config"
	"dirLocker/pkg/logging"
)

// KDFParams represents Argon2id key derivation parameters
type KDFParams struct {
	Memory      uint32 `json:"memory"`      // Memory usage in KB
	Operations  uint32 `json:"operations"`  // Number of iterations
	Parallelism uint32 `json:"parallelism"` // Degree of parallelism
}

// VaultManager provides high-level vault operations and management
type VaultManager struct {
	config     *config.Config
	logger     *logging.Logger
	openVaults map[string]*ManagedVault
	mutex      sync.RWMutex
}

// ManagedVault represents a vault with additional management metadata
type ManagedVault struct {
	Handle   *VaultHandle
	Path     string
	OpenedAt time.Time
	LastUsed time.Time
	IsShared bool
	mutex    sync.RWMutex
}

// VaultInfo contains metadata about a vault
type VaultInfo struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
	ModifiedAt   time.Time `json:"modified_at"`
	IsAccessible bool      `json:"is_accessible"`
	Cipher       string    `json:"cipher,omitempty"`
}

// NewVaultManager creates a new vault manager instance
func NewVaultManager(cfg *config.Config, logger *logging.Logger) *VaultManager {
	return &VaultManager{
		config:     cfg,
		logger:     logger,
		openVaults: make(map[string]*ManagedVault),
	}
}

// CreateVaultWithParams creates a new vault with custom KDF parameters
func (vm *VaultManager) CreateVaultWithParams(path, password string, cipher CipherType, kdfParams *KDFParams) error {
	vm.logger.Info("Creating new vault with custom parameters", "path", path, "cipher", cipher)

	// Use default parameters if not specified
	if kdfParams == nil {
		kdfParams = &KDFParams{
			Memory:      65536, // 64MB
			Operations:  3,
			Parallelism: 1,
		}
	} else {
		// Apply defaults for unspecified parameters
		if kdfParams.Memory == 0 {
			kdfParams.Memory = 65536
		}
		if kdfParams.Operations == 0 {
			kdfParams.Operations = 3
		}
		if kdfParams.Parallelism == 0 {
			kdfParams.Parallelism = 1
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		vm.logger.Error("Failed to create vault directory", "error", err, "dir", dir)
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Check if vault already exists
	if _, err := os.Stat(path); err == nil {
		vm.logger.Warn("Vault already exists", "path", path)
		return fmt.Errorf("vault already exists at path: %s", path)
	}

	// Create the vault using core library with custom parameters
	handle, err := CreateVaultWithKDF(path, password, cipher, kdfParams)
	if err != nil {
		vm.logger.Error("Failed to create vault with custom parameters", "error", err, "path", path)
		return fmt.Errorf("failed to create vault: %w", err)
	}

	// Close the handle immediately after creation
	if err := handle.Close(); err != nil {
		vm.logger.Warn("Failed to close vault handle after creation", "error", err)
	}

	vm.logger.Info("Successfully created vault with custom parameters", "path", path, "kdf", kdfParams)
	return nil
}

// CreateVault creates a new vault with the specified parameters
func (vm *VaultManager) CreateVault(path, password string, cipher CipherType) error {
	vm.logger.Info("Creating new vault", "path", path, "cipher", cipher)

	// Validate path for invalid characters
	if strings.Contains(path, "\x00") {
		vm.logger.Error("Invalid vault path contains null bytes", "path", path)
		return fmt.Errorf("invalid vault path: contains null bytes")
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		vm.logger.Error("Failed to create vault directory", "error", err, "dir", dir)
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Check if vault already exists
	if _, err := os.Stat(path); err == nil {
		vm.logger.Warn("Vault already exists", "path", path)
		return fmt.Errorf("vault already exists at path: %s", path)
	}

	// Create the vault using core library
	handle, err := CreateVault(path, password, cipher)
	if err != nil {
		vm.logger.Error("Failed to create vault", "error", err, "path", path)
		return fmt.Errorf("failed to create vault: %w", err)
	}

	// Close the handle immediately after creation
	if err := handle.Close(); err != nil {
		vm.logger.Warn("Failed to close vault handle after creation", "error", err)
	}

	vm.logger.Info("Successfully created vault", "path", path)
	return nil
}

// OpenVault opens an existing vault and adds it to the managed vaults
func (vm *VaultManager) OpenVault(path, password string) (*ManagedVault, error) {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Check if vault is already open
	if vault, exists := vm.openVaults[path]; exists {
		vault.mutex.Lock()
		vault.LastUsed = time.Now()
		vault.mutex.Unlock()
		vm.logger.Debug("Vault already open, returning existing handle", "path", path)
		return vault, nil
	}

	vm.logger.Info("Opening vault", "path", path)

	// Check if vault file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		vm.logger.Error("Vault file does not exist", "path", path)
		return nil, fmt.Errorf("vault file does not exist: %s", path)
	}

	// Open the vault using core library
	unlockMaterial := &UnlockMaterial{Password: password}
	handle, err := OpenVault(path, unlockMaterial)
	if err != nil {
		vm.logger.Error("Failed to open vault", "error", err, "path", path)
		return nil, fmt.Errorf("failed to open vault: %w", err)
	}

	// Create managed vault
	managedVault := &ManagedVault{
		Handle:   handle,
		Path:     path,
		OpenedAt: time.Now(),
		LastUsed: time.Now(),
		IsShared: false,
	}

	vm.openVaults[path] = managedVault
	vm.logger.Info("Successfully opened vault", "path", path)
	return managedVault, nil
}

// OpenVaultWithRecipientKey opens a shared vault using recipient's private key
func (vm *VaultManager) OpenVaultWithRecipientKey(path string, privateKey [32]byte, envelopesJSON string) (*ManagedVault, error) {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Check if vault is already open
	if vault, exists := vm.openVaults[path]; exists {
		vault.mutex.Lock()
		vault.LastUsed = time.Now()
		vault.mutex.Unlock()
		vm.logger.Debug("Shared vault already open, returning existing handle", "path", path)
		return vault, nil
	}

	vm.logger.Info("Opening shared vault with recipient key", "path", path)

	// Check if vault file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		vm.logger.Error("Vault file does not exist", "path", path)
		return nil, fmt.Errorf("vault file does not exist: %s", path)
	}

	// Open the vault using recipient key
	handle, err := OpenWithRecipientKey(path, privateKey, envelopesJSON)
	if err != nil {
		vm.logger.Error("Failed to open shared vault", "error", err, "path", path)
		return nil, fmt.Errorf("failed to open shared vault: %w", err)
	}

	// Create managed vault
	managedVault := &ManagedVault{
		Handle:   handle,
		Path:     path,
		OpenedAt: time.Now(),
		LastUsed: time.Now(),
		IsShared: true,
	}

	vm.openVaults[path] = managedVault
	vm.logger.Info("Successfully opened shared vault", "path", path)
	return managedVault, nil
}

// CloseVault closes a vault and removes it from managed vaults
func (vm *VaultManager) CloseVault(path string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	vault, exists := vm.openVaults[path]
	if !exists {
		vm.logger.Warn("Attempted to close vault that is not open", "path", path)
		return fmt.Errorf("vault is not open: %s", path)
	}

	vm.logger.Info("Closing vault", "path", path)

	vault.mutex.Lock()
	err := vault.Handle.Close()
	vault.mutex.Unlock()

	if err != nil {
		vm.logger.Error("Failed to close vault handle", "error", err, "path", path)
		return fmt.Errorf("failed to close vault: %w", err)
	}

	delete(vm.openVaults, path)
	vm.logger.Info("Successfully closed vault", "path", path)
	return nil
}

// CloseAllVaults closes all open vaults
func (vm *VaultManager) CloseAllVaults() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	vm.logger.Info("Closing all open vaults", "count", len(vm.openVaults))

	var errors []error
	for path, vault := range vm.openVaults {
		vault.mutex.Lock()
		if err := vault.Handle.Close(); err != nil {
			vm.logger.Error("Failed to close vault", "error", err, "path", path)
			errors = append(errors, fmt.Errorf("failed to close vault %s: %w", path, err))
		}
		vault.mutex.Unlock()
	}

	// Clear the map
	vm.openVaults = make(map[string]*ManagedVault)

	if len(errors) > 0 {
		return fmt.Errorf("failed to close %d vaults: %v", len(errors), errors)
	}

	vm.logger.Info("Successfully closed all vaults")
	return nil
}

// GetVault returns a managed vault by path
func (vm *VaultManager) GetVault(path string) (*ManagedVault, bool) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vault, exists := vm.openVaults[path]
	if exists {
		vault.mutex.Lock()
		vault.LastUsed = time.Now()
		vault.mutex.Unlock()
	}

	return vault, exists
}

// ListOpenVaults returns a list of all open vaults
func (vm *VaultManager) ListOpenVaults() []string {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	paths := make([]string, 0, len(vm.openVaults))
	for path := range vm.openVaults {
		paths = append(paths, path)
	}

	return paths
}

// GetVaultInfo returns metadata about a vault file
func (vm *VaultManager) GetVaultInfo(path string) (*VaultInfo, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat vault file: %w", err)
	}

	info := &VaultInfo{
		Path:         path,
		Size:         stat.Size(),
		ModifiedAt:   stat.ModTime(),
		IsAccessible: true,
	}

	// Try to determine creation time (platform-specific)
	if sys := stat.Sys(); sys != nil {
		// This is platform-specific and may not work on all systems
		info.CreatedAt = stat.ModTime() // Fallback to modification time
	}

	return info, nil
}

// ChangeVaultPassword changes the password for a vault
func (vm *VaultManager) ChangeVaultPassword(path, oldPassword, newPassword string) error {
	vm.logger.Info("Changing vault password", "path", path)

	// Check if vault is currently open
	vault, isOpen := vm.GetVault(path)
	if isOpen {
		// Use the open vault handle
		vault.mutex.Lock()
		err := vault.Handle.ChangePassword(oldPassword, newPassword)
		vault.mutex.Unlock()

		if err != nil {
			vm.logger.Error("Failed to change password for open vault", "error", err, "path", path)
			return fmt.Errorf("failed to change password: %w", err)
		}
	} else {
		// Open vault temporarily to change password
		unlockMaterial := &UnlockMaterial{Password: oldPassword}
		handle, err := OpenVault(path, unlockMaterial)
		if err != nil {
			vm.logger.Error("Failed to open vault for password change", "error", err, "path", path)
			return fmt.Errorf("failed to open vault for password change: %w", err)
		}
		defer handle.Close()

		if err := handle.ChangePassword(oldPassword, newPassword); err != nil {
			vm.logger.Error("Failed to change vault password", "error", err, "path", path)
			return fmt.Errorf("failed to change password: %w", err)
		}
	}

	vm.logger.Info("Successfully changed vault password", "path", path)
	return nil
}

// GenerateRecoveryKey generates a recovery key for a vault
func (vm *VaultManager) GenerateRecoveryKey(path, password string) (*RecoveryKey, *WrappedMasterKey, error) {
	vm.logger.Info("Generating recovery key", "path", path)

	// Check if vault is currently open
	vault, isOpen := vm.GetVault(path)
	if isOpen {
		// Use the open vault handle
		vault.mutex.Lock()
		recoveryKey, wrappedKey, err := vault.Handle.GenerateRecoveryKey(password)
		vault.mutex.Unlock()

		if err != nil {
			vm.logger.Error("Failed to generate recovery key for open vault", "error", err, "path", path)
			return nil, nil, fmt.Errorf("failed to generate recovery key: %w", err)
		}

		vm.logger.Info("Successfully generated recovery key", "path", path)
		return recoveryKey, wrappedKey, nil
	} else {
		// Open vault temporarily to generate recovery key
		unlockMaterial := &UnlockMaterial{Password: password}
		handle, err := OpenVault(path, unlockMaterial)
		if err != nil {
			vm.logger.Error("Failed to open vault for recovery key generation", "error", err, "path", path)
			return nil, nil, fmt.Errorf("failed to open vault for recovery key generation: %w", err)
		}
		defer handle.Close()

		recoveryKey, wrappedKey, err := handle.GenerateRecoveryKey(password)
		if err != nil {
			vm.logger.Error("Failed to generate recovery key", "error", err, "path", path)
			return nil, nil, fmt.Errorf("failed to generate recovery key: %w", err)
		}

		vm.logger.Info("Successfully generated recovery key", "path", path)
		return recoveryKey, wrappedKey, nil
	}
}

// RecoverVault recovers vault access using recovery key
func (vm *VaultManager) RecoverVault(path string, recoveryKey *RecoveryKey, wrappedKey *WrappedMasterKey, newPassword string) error {
	vm.logger.Info("Recovering vault with recovery key", "path", path)

	if err := RecoverWithKey(path, recoveryKey, wrappedKey, newPassword); err != nil {
		vm.logger.Error("Failed to recover vault", "error", err, "path", path)
		return fmt.Errorf("failed to recover vault: %w", err)
	}

	vm.logger.Info("Successfully recovered vault", "path", path)
	return nil
}

// AutoCloseIdleVaults closes vaults that have been idle for too long
func (vm *VaultManager) AutoCloseIdleVaults() {
	if vm.config.AutoLockTimeout <= 0 {
		return // Auto-close disabled
	}

	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	now := time.Now()
	var toClose []string

	for path, vault := range vm.openVaults {
		vault.mutex.RLock()
		if now.Sub(vault.LastUsed) > vm.config.AutoLockTimeout {
			toClose = append(toClose, path)
		}
		vault.mutex.RUnlock()
	}

	for _, path := range toClose {
		vm.logger.Info("Auto-closing idle vault", "path", path)
		vault := vm.openVaults[path]
		vault.mutex.Lock()
		if err := vault.Handle.Close(); err != nil {
			vm.logger.Error("Failed to auto-close idle vault", "error", err, "path", path)
		}
		vault.mutex.Unlock()
		delete(vm.openVaults, path)
	}

	if len(toClose) > 0 {
		vm.logger.Info("Auto-closed idle vaults", "count", len(toClose))
	}
}

// StartAutoCloseTimer starts a timer to automatically close idle vaults
func (vm *VaultManager) StartAutoCloseTimer() {
	if vm.config.AutoLockTimeout <= 0 {
		return // Auto-close disabled
	}

	ticker := time.NewTicker(vm.config.AutoLockTimeout / 2) // Check twice as often as timeout
	go func() {
		for range ticker.C {
			vm.AutoCloseIdleVaults()
		}
	}()

	vm.logger.Info("Started auto-close timer", "timeout", vm.config.AutoLockTimeout)
}

// UpdateLastUsed updates the last used time for a vault
func (mv *ManagedVault) UpdateLastUsed() {
	mv.mutex.Lock()
	defer mv.mutex.Unlock()
	mv.LastUsed = time.Now()
}

// GetInfo returns information about the managed vault
func (mv *ManagedVault) GetInfo() (path string, openedAt, lastUsed time.Time, isShared bool) {
	mv.mutex.RLock()
	defer mv.mutex.RUnlock()
	return mv.Path, mv.OpenedAt, mv.LastUsed, mv.IsShared
}

// ListFiles lists all files and directories in the managed vault
func (mv *ManagedVault) ListFiles() ([]FileEntry, error) {
	mv.mutex.Lock()
	defer mv.mutex.Unlock()
	mv.LastUsed = time.Now()
	return mv.Handle.ListFiles()
}

// AddFile adds a file to the managed vault
func (mv *ManagedVault) AddFile(vaultPath string, data []byte) error {
	mv.mutex.Lock()
	defer mv.mutex.Unlock()
	mv.LastUsed = time.Now()
	return mv.Handle.AddFile(vaultPath, data)
}

// ExtractFile extracts a file from the managed vault
func (mv *ManagedVault) ExtractFile(vaultPath string) ([]byte, error) {
	mv.mutex.Lock()
	defer mv.mutex.Unlock()
	mv.LastUsed = time.Now()
	return mv.Handle.ExtractFile(vaultPath)
}

// DeleteFile deletes a file from the managed vault
func (mv *ManagedVault) DeleteFile(vaultPath string) error {
	mv.mutex.Lock()
	defer mv.mutex.Unlock()
	mv.LastUsed = time.Now()
	return mv.Handle.DeleteFile(vaultPath)
}

// CreateDirectory creates a directory in the managed vault
func (mv *ManagedVault) CreateDirectory(vaultPath string) error {
	mv.mutex.Lock()
	defer mv.mutex.Unlock()
	mv.LastUsed = time.Now()
	return mv.Handle.CreateDirectory(vaultPath)
}

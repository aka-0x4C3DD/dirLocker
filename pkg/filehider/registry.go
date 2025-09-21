package filehider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
)

const (
	registryVersion = 1
	saltSize        = 32
	nonceSize       = 12
	keySize         = 32
	iterations      = 100000
)

// EncryptedRegistry manages the encrypted storage of hidden file metadata
type EncryptedRegistry struct {
	registryPath string
	password     string
}

// NewEncryptedRegistry creates a new encrypted registry instance
func NewEncryptedRegistry(registryPath, password string) *EncryptedRegistry {
	return &EncryptedRegistry{
		registryPath: registryPath,
		password:     password,
	}
}

// Load reads and decrypts the registry from disk
func (er *EncryptedRegistry) Load() (*HiddenFileRegistry, error) {
	// Check if registry file exists
	if _, err := os.Stat(er.registryPath); os.IsNotExist(err) {
		// Create new empty registry
		return &HiddenFileRegistry{
			Version: registryVersion,
			Files:   make(map[string]HiddenFileInfo),
			Salt:    make([]byte, saltSize),
		}, nil
	}

	// Read encrypted registry file
	encryptedData, err := os.ReadFile(er.registryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read registry file: %w", err)
	}

	if len(encryptedData) < saltSize+nonceSize {
		return nil, fmt.Errorf("registry file too small to be valid")
	}

	// Extract salt and nonce
	salt := encryptedData[:saltSize]
	nonce := encryptedData[saltSize : saltSize+nonceSize]
	ciphertext := encryptedData[saltSize+nonceSize:]

	// Derive key from password and salt
	key := pbkdf2.Key([]byte(er.password), salt, iterations, keySize, sha256.New)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt registry: %w", err)
	}

	// Unmarshal JSON
	var registry HiddenFileRegistry
	if err := json.Unmarshal(plaintext, &registry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal registry: %w", err)
	}

	return &registry, nil
}

// Save encrypts and writes the registry to disk
func (er *EncryptedRegistry) Save(registry *HiddenFileRegistry) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(er.registryPath), 0700); err != nil {
		return fmt.Errorf("failed to create registry directory: %w", err)
	}

	// Generate salt if not present
	if len(registry.Salt) == 0 {
		registry.Salt = make([]byte, saltSize)
		if _, err := rand.Read(registry.Salt); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	// Marshal registry to JSON
	plaintext, err := json.Marshal(registry)
	if err != nil {
		return fmt.Errorf("failed to marshal registry: %w", err)
	}

	// Derive key from password and salt
	key := pbkdf2.Key([]byte(er.password), registry.Salt, iterations, keySize, sha256.New)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Combine salt, nonce, and ciphertext
	encryptedData := make([]byte, 0, saltSize+nonceSize+len(ciphertext))
	encryptedData = append(encryptedData, registry.Salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	// Write to temporary file first, then rename (atomic operation)
	tempPath := er.registryPath + ".tmp"
	if err := os.WriteFile(tempPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write temporary registry file: %w", err)
	}

	if err := os.Rename(tempPath, er.registryPath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename registry file: %w", err)
	}

	return nil
}

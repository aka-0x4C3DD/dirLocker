//go:build !cgo
// +build !cgo

package vault

import (
	"errors"
	"fmt"
)

// Stub implementations for when CGO is not available

// CipherType represents the encryption algorithm to use
type CipherType int

const (
	CipherAES256GCM         CipherType = 0
	CipherXChaCha20Poly1305 CipherType = 1
)

// ErrorCode represents vault operation error codes
type ErrorCode int

const (
	ErrorSuccess           ErrorCode = 0
	ErrorInvalidPassword   ErrorCode = 1
	ErrorCorruptedVault    ErrorCode = 2
	ErrorUnsupportedCipher ErrorCode = 3
	ErrorFileNotFound      ErrorCode = 4
	ErrorInsufficientSpace ErrorCode = 5
	ErrorPermissionDenied  ErrorCode = 6
	ErrorInvalidArgument   ErrorCode = 7
	ErrorInternalError     ErrorCode = 8
)

// VaultError represents a vault operation error
type VaultError struct {
	Code    ErrorCode
	Message string
}

func (e *VaultError) Error() string {
	return fmt.Sprintf("vault error %d: %s", e.Code, e.Message)
}

// VaultHandle represents an opaque handle to a vault instance
type VaultHandle struct {
	// Stub implementation - no fields needed
}

// UnlockMaterial contains credentials for opening a vault
type UnlockMaterial struct {
	Password    string
	RecoveryKey []byte
}

// FileEntry represents a file or directory in the vault
type FileEntry struct {
	Name  string
	Size  uint64
	IsDir bool
	MTime int64
	Mode  uint32
}

// X25519KeyPair represents a key pair for secure sharing
type X25519KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// RecoveryKey represents a recovery key for vault access
type RecoveryKey struct {
	KeyData [32]byte
}

// WrappedMasterKey represents an encrypted master key
type WrappedMasterKey struct {
	EncryptedKey []byte
	Nonce        []byte
	Cipher       string
	Salt         []byte
	Memory       uint32
	Operations   uint32
	Parallelism  uint32
}

// Envelope represents a sharing envelope for secure key sharing
type Envelope struct {
	RecipientPublicKey [32]byte
	EncryptedKey       []byte
	Nonce              [24]byte
}

// Stub implementations that return "not implemented" errors

// CreateVault creates a new vault container (stub)
func CreateVault(path, password string, cipher CipherType) (*VaultHandle, error) {
	return nil, errors.New("CGO not available - vault operations require Rust core library")
}

// CreateVaultWithKDF creates a new vault container with custom KDF parameters (stub)
func CreateVaultWithKDF(path, password string, cipher CipherType, kdfParams *KDFParams) (*VaultHandle, error) {
	return nil, errors.New("CGO not available - vault operations require Rust core library")
}

// OpenVault opens an existing vault container (stub)
func OpenVault(path string, unlockMaterial *UnlockMaterial) (*VaultHandle, error) {
	return nil, errors.New("CGO not available - vault operations require Rust core library")
}

// Close closes the vault and frees its resources (stub)
func (v *VaultHandle) Close() error {
	return errors.New("CGO not available - vault operations require Rust core library")
}

// ChangePassword changes the vault password (stub)
func (v *VaultHandle) ChangePassword(oldPassword, newPassword string) error {
	return errors.New("CGO not available - vault operations require Rust core library")
}

// GenerateRecoveryKey generates a recovery key for the vault (stub)
func (v *VaultHandle) GenerateRecoveryKey(password string) (*RecoveryKey, *WrappedMasterKey, error) {
	return nil, nil, errors.New("CGO not available - vault operations require Rust core library")
}

// GenerateSharingKeyPair generates a new X25519 key pair for sharing (stub)
func GenerateSharingKeyPair() (*X25519KeyPair, error) {
	return nil, errors.New("CGO not available - vault operations require Rust core library")
}

// AddSharingRecipient adds a recipient for secure sharing (stub)
func (v *VaultHandle) AddSharingRecipient(publicKey [32]byte) error {
	return errors.New("CGO not available - vault operations require Rust core library")
}

// RemoveSharingRecipient removes a recipient from secure sharing (stub)
func (v *VaultHandle) RemoveSharingRecipient(publicKey [32]byte) (bool, error) {
	return false, errors.New("CGO not available - vault operations require Rust core library")
}

// SharingRecipientCount returns the number of sharing recipients (stub)
func (v *VaultHandle) SharingRecipientCount() (int, error) {
	return 0, errors.New("CGO not available - vault operations require Rust core library")
}

// ExportSharingEnvelopes exports sharing envelopes as JSON string (stub)
func (v *VaultHandle) ExportSharingEnvelopes() (string, error) {
	return "", errors.New("CGO not available - vault operations require Rust core library")
}

// ImportSharingEnvelopes imports sharing envelopes from JSON string (stub)
func (v *VaultHandle) ImportSharingEnvelopes(jsonStr string) error {
	return errors.New("CGO not available - vault operations require Rust core library")
}

// OpenWithRecipientKey opens vault using recipient's private key (stub)
func OpenWithRecipientKey(path string, privateKey [32]byte, envelopesJSON string) (*VaultHandle, error) {
	return nil, errors.New("CGO not available - vault operations require Rust core library")
}

// RecoveryKeyToHex converts recovery key to hex string (stub)
func (r *RecoveryKey) ToHex() (string, error) {
	return "", errors.New("CGO not available - vault operations require Rust core library")
}

// RecoveryKeyFromHex creates recovery key from hex string (stub)
func RecoveryKeyFromHex(hexStr string) (*RecoveryKey, error) {
	return nil, errors.New("CGO not available - vault operations require Rust core library")
}

// RecoverWithKey recovers vault access using recovery key (stub)
func RecoverWithKey(path string, recoveryKey *RecoveryKey, wrappedKey *WrappedMasterKey, newPassword string) error {
	return errors.New("CGO not available - vault operations require Rust core library")
}

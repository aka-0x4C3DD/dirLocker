//go:build cgo
// +build cgo

package vault

/*
#cgo CFLAGS: -I../../vault-core
#cgo windows LDFLAGS: -L../../vault-core/target/x86_64-pc-windows-gnu/release -l:libvault_core.a -lws2_32 -ladvapi32 -luserenv -lbcrypt -lntdll
#cgo linux LDFLAGS: -L../../vault-core/target/release -lvault_core -ldl -lm
#cgo darwin LDFLAGS: -L../../vault-core/target/release -lvault_core -framework Security -framework CoreFoundation

#include "vault_core.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

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
	handle C.CVaultHandle
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

// getLastError retrieves the last error from the core library
func getLastError() *VaultError {
	errorCode := C.vault_get_last_error()
	if errorCode == C.ERROR_SUCCESS {
		return nil
	}

	messagePtr := C.vault_error_message(errorCode)
	message := C.GoString(messagePtr)

	return &VaultError{
		Code:    ErrorCode(errorCode),
		Message: message,
	}
}

// CreateVault creates a new vault container
func CreateVault(path, password string, cipher CipherType) (*VaultHandle, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	handle := C.vault_create(cPath, cPassword, C.CCipherType(cipher))
	if handle == nil {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorInternalError, Message: "Failed to create vault"}
	}

	vault := &VaultHandle{handle: handle}
	runtime.SetFinalizer(vault, (*VaultHandle).Close)
	return vault, nil
}

// CreateVaultWithKDF creates a new vault container with custom KDF parameters
func CreateVaultWithKDF(path, password string, cipher CipherType, kdfParams *KDFParams) (*VaultHandle, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	// For now, use the standard create function
	// In a full implementation, this would pass KDF parameters to the C library
	handle := C.vault_create(cPath, cPassword, C.CCipherType(cipher))
	if handle == nil {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorInternalError, Message: "Failed to create vault with KDF parameters"}
	}

	vault := &VaultHandle{handle: handle}
	runtime.SetFinalizer(vault, (*VaultHandle).Close)
	return vault, nil
}

// OpenVault opens an existing vault container
func OpenVault(path string, unlockMaterial *UnlockMaterial) (*VaultHandle, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var cUnlock C.CUnlockMaterial
	if unlockMaterial.Password != "" {
		cPassword := C.CString(unlockMaterial.Password)
		defer C.free(unsafe.Pointer(cPassword))
		cUnlock.password = cPassword
	}

	if len(unlockMaterial.RecoveryKey) > 0 {
		cUnlock.recovery_key = (*C.uchar)(unsafe.Pointer(&unlockMaterial.RecoveryKey[0]))
		cUnlock.recovery_key_len = C.size_t(len(unlockMaterial.RecoveryKey))
	}

	handle := C.vault_open(cPath, &cUnlock)
	if handle == nil {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorInternalError, Message: "Failed to open vault"}
	}

	vault := &VaultHandle{handle: handle}
	runtime.SetFinalizer(vault, (*VaultHandle).Close)
	return vault, nil
}

// Close closes the vault and frees its resources
func (v *VaultHandle) Close() error {
	if v.handle != nil {
		result := C.vault_close(v.handle)
		v.handle = nil
		runtime.SetFinalizer(v, nil)

		if result != C.ERROR_SUCCESS {
			if err := getLastError(); err != nil {
				return err
			}
			return &VaultError{Code: ErrorInternalError, Message: "Failed to close vault"}
		}
	}
	return nil
}

// ChangePassword changes the vault password without re-encrypting chunks
func (v *VaultHandle) ChangePassword(oldPassword, newPassword string) error {
	if v.handle == nil {
		return &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	cOldPassword := C.CString(oldPassword)
	defer C.free(unsafe.Pointer(cOldPassword))

	cNewPassword := C.CString(newPassword)
	defer C.free(unsafe.Pointer(cNewPassword))

	result := C.vault_change_password(v.handle, cOldPassword, cNewPassword)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to change password"}
	}

	return nil
}

// GenerateRecoveryKey generates a recovery key for the vault
func (v *VaultHandle) GenerateRecoveryKey(password string) (*RecoveryKey, *WrappedMasterKey, error) {
	if v.handle == nil {
		return nil, nil, &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	var cRecoveryKey C.CRecoveryKey
	var cWrappedKey C.CWrappedMasterKey

	result := C.vault_generate_recovery_key(v.handle, cPassword, &cRecoveryKey, &cWrappedKey)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return nil, nil, err
		}
		return nil, nil, &VaultError{Code: ErrorCode(result), Message: "Failed to generate recovery key"}
	}

	// Convert C structures to Go structures
	var keyData [32]byte
	for i := 0; i < 32; i++ {
		keyData[i] = byte(cRecoveryKey.key_data[i])
	}
	recoveryKey := &RecoveryKey{
		KeyData: keyData,
	}

	encryptedKey := C.GoBytes(unsafe.Pointer(cWrappedKey.encrypted_key), C.int(cWrappedKey.encrypted_key_len))
	nonce := C.GoBytes(unsafe.Pointer(cWrappedKey.nonce), C.int(cWrappedKey.nonce_len))
	salt := C.GoBytes(unsafe.Pointer(cWrappedKey.salt), C.int(cWrappedKey.salt_len))
	cipher := C.GoString(cWrappedKey.cipher)

	wrappedKey := &WrappedMasterKey{
		EncryptedKey: encryptedKey,
		Nonce:        nonce,
		Cipher:       cipher,
		Salt:         salt,
		Memory:       uint32(cWrappedKey.memory),
		Operations:   uint32(cWrappedKey.operations),
		Parallelism:  uint32(cWrappedKey.parallelism),
	}

	// Free C allocated memory
	C.vault_free_wrapped_key(&cWrappedKey)

	return recoveryKey, wrappedKey, nil
}

// GenerateSharingKeyPair generates a new X25519 key pair for sharing
func GenerateSharingKeyPair() (*X25519KeyPair, error) {
	var cKeyPair C.CX25519KeyPair

	result := C.vault_generate_sharing_keypair(&cKeyPair)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorCode(result), Message: "Failed to generate sharing key pair"}
	}

	var publicKey, privateKey [32]byte
	for i := 0; i < 32; i++ {
		publicKey[i] = byte(cKeyPair.public_key[i])
		privateKey[i] = byte(cKeyPair.private_key[i])
	}
	keyPair := &X25519KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	return keyPair, nil
}

// AddSharingRecipient adds a recipient for secure sharing
func (v *VaultHandle) AddSharingRecipient(publicKey [32]byte) error {
	if v.handle == nil {
		return &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	result := C.vault_add_sharing_recipient(v.handle, (*C.uchar)(unsafe.Pointer(&publicKey[0])))
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to add sharing recipient"}
	}

	return nil
}

// RemoveSharingRecipient removes a recipient from secure sharing
func (v *VaultHandle) RemoveSharingRecipient(publicKey [32]byte) (bool, error) {
	if v.handle == nil {
		return false, &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	result := C.vault_remove_sharing_recipient(v.handle, (*C.uchar)(unsafe.Pointer(&publicKey[0])))
	if result < 0 {
		if err := getLastError(); err != nil {
			return false, err
		}
		return false, &VaultError{Code: ErrorCode(-result), Message: "Failed to remove sharing recipient"}
	}

	return result == 1, nil
}

// SharingRecipientCount returns the number of sharing recipients
func (v *VaultHandle) SharingRecipientCount() (int, error) {
	if v.handle == nil {
		return 0, &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	result := C.vault_sharing_recipient_count(v.handle)
	if result < 0 {
		if err := getLastError(); err != nil {
			return 0, err
		}
		return 0, &VaultError{Code: ErrorCode(-result), Message: "Failed to get sharing recipient count"}
	}

	return int(result), nil
}

// ExportSharingEnvelopes exports sharing envelopes as JSON string
func (v *VaultHandle) ExportSharingEnvelopes() (string, error) {
	if v.handle == nil {
		return "", &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	var cJsonOut *C.char
	result := C.vault_export_sharing_envelopes(v.handle, &cJsonOut)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return "", err
		}
		return "", &VaultError{Code: ErrorCode(result), Message: "Failed to export sharing envelopes"}
	}

	jsonStr := C.GoString(cJsonOut)
	C.vault_free_string(cJsonOut)

	return jsonStr, nil
}

// ImportSharingEnvelopes imports sharing envelopes from JSON string
func (v *VaultHandle) ImportSharingEnvelopes(jsonStr string) error {
	if v.handle == nil {
		return &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	cJson := C.CString(jsonStr)
	defer C.free(unsafe.Pointer(cJson))

	result := C.vault_import_sharing_envelopes(v.handle, cJson)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to import sharing envelopes"}
	}

	return nil
}

// OpenWithRecipientKey opens vault using recipient's private key for shared access
func OpenWithRecipientKey(path string, privateKey [32]byte, envelopesJSON string) (*VaultHandle, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cEnvelopes := C.CString(envelopesJSON)
	defer C.free(unsafe.Pointer(cEnvelopes))

	handle := C.vault_open_with_recipient_key(cPath, (*C.uchar)(unsafe.Pointer(&privateKey[0])), cEnvelopes)
	if handle == nil {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorInternalError, Message: "Failed to open vault with recipient key"}
	}

	vault := &VaultHandle{handle: handle}
	runtime.SetFinalizer(vault, (*VaultHandle).Close)
	return vault, nil
}

// RecoveryKeyToHex converts recovery key to hex string
func (r *RecoveryKey) ToHex() (string, error) {
	var cHexOut *C.char
	result := C.vault_recovery_key_to_hex((*C.CRecoveryKey)(unsafe.Pointer(r)), &cHexOut)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return "", err
		}
		return "", &VaultError{Code: ErrorCode(result), Message: "Failed to convert recovery key to hex"}
	}

	hexStr := C.GoString(cHexOut)
	C.vault_free_string(cHexOut)

	return hexStr, nil
}

// RecoveryKeyFromHex creates recovery key from hex string
func RecoveryKeyFromHex(hexStr string) (*RecoveryKey, error) {
	cHex := C.CString(hexStr)
	defer C.free(unsafe.Pointer(cHex))

	var cRecoveryKey C.CRecoveryKey
	result := C.vault_recovery_key_from_hex(cHex, &cRecoveryKey)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorCode(result), Message: "Failed to create recovery key from hex"}
	}

	var keyData [32]byte
	for i := 0; i < 32; i++ {
		keyData[i] = byte(cRecoveryKey.key_data[i])
	}
	return &RecoveryKey{KeyData: keyData}, nil
}

// RecoverWithKey recovers vault access using recovery key
func RecoverWithKey(path string, recoveryKey *RecoveryKey, wrappedKey *WrappedMasterKey, newPassword string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cNewPassword := C.CString(newPassword)
	defer C.free(unsafe.Pointer(cNewPassword))

	// Convert Go structures to C structures
	cRecoveryKey := (*C.CRecoveryKey)(unsafe.Pointer(recoveryKey))

	var cWrappedKey C.CWrappedMasterKey
	cWrappedKey.encrypted_key = (*C.uchar)(C.CBytes(wrappedKey.EncryptedKey))
	cWrappedKey.encrypted_key_len = C.size_t(len(wrappedKey.EncryptedKey))
	cWrappedKey.nonce = (*C.uchar)(C.CBytes(wrappedKey.Nonce))
	cWrappedKey.nonce_len = C.size_t(len(wrappedKey.Nonce))
	cWrappedKey.salt = (*C.uchar)(C.CBytes(wrappedKey.Salt))
	cWrappedKey.salt_len = C.size_t(len(wrappedKey.Salt))
	cWrappedKey.cipher = C.CString(wrappedKey.Cipher)
	cWrappedKey.memory = C.uint(wrappedKey.Memory)
	cWrappedKey.operations = C.uint(wrappedKey.Operations)
	cWrappedKey.parallelism = C.uint(wrappedKey.Parallelism)

	defer func() {
		C.free(unsafe.Pointer(cWrappedKey.encrypted_key))
		C.free(unsafe.Pointer(cWrappedKey.nonce))
		C.free(unsafe.Pointer(cWrappedKey.salt))
		C.free(unsafe.Pointer(cWrappedKey.cipher))
	}()

	result := C.vault_recover_with_key(cPath, cRecoveryKey, &cWrappedKey, cNewPassword)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to recover vault with key"}
	}

	return nil
}

// ListFiles lists all files and directories in the vault
func (v *VaultHandle) ListFiles() ([]FileEntry, error) {
	if v.handle == nil {
		return nil, &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	var cEntries *C.CFileEntry
	var count C.size_t

	result := C.vault_list_files(v.handle, &cEntries, &count)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorCode(result), Message: "Failed to list files"}
	}

	// Convert C array to Go slice
	entries := make([]FileEntry, count)
	if count > 0 {
		cEntriesSlice := (*[1 << 30]C.CFileEntry)(unsafe.Pointer(cEntries))[:count:count]

		for i, cEntry := range cEntriesSlice {
			entries[i] = FileEntry{
				Name:  C.GoString(cEntry.name),
				Size:  uint64(cEntry.size),
				IsDir: cEntry.is_dir != 0,
				MTime: int64(cEntry.mtime),
				Mode:  uint32(cEntry.mode),
			}
		}

		// Free C allocated memory
		C.vault_free_file_entries(cEntries, count)
	}

	return entries, nil
}

// AddFile adds a file to the vault
func (v *VaultHandle) AddFile(vaultPath string, data []byte) error {
	if v.handle == nil {
		return &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	cPath := C.CString(vaultPath)
	defer C.free(unsafe.Pointer(cPath))

	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}

	result := C.vault_write_file(v.handle, cPath, dataPtr, C.size_t(len(data)))
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to add file"}
	}

	return nil
}

// ExtractFile extracts a file from the vault
func (v *VaultHandle) ExtractFile(vaultPath string) ([]byte, error) {
	if v.handle == nil {
		return nil, &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	cPath := C.CString(vaultPath)
	defer C.free(unsafe.Pointer(cPath))

	var cData *C.uint8_t
	var size C.size_t

	result := C.vault_read_file(v.handle, cPath, &cData, &size)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return nil, err
		}
		return nil, &VaultError{Code: ErrorCode(result), Message: "Failed to extract file"}
	}

	data := C.GoBytes(unsafe.Pointer(cData), C.int(size))
	C.vault_free_file_data(cData)

	return data, nil
}

// DeleteFile deletes a file from the vault
func (v *VaultHandle) DeleteFile(vaultPath string) error {
	if v.handle == nil {
		return &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	cPath := C.CString(vaultPath)
	defer C.free(unsafe.Pointer(cPath))

	result := C.vault_delete_file(v.handle, cPath)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to delete file"}
	}

	return nil
}

// CreateDirectory creates a directory in the vault
func (v *VaultHandle) CreateDirectory(vaultPath string) error {
	if v.handle == nil {
		return &VaultError{Code: ErrorInvalidArgument, Message: "Vault handle is null"}
	}

	cPath := C.CString(vaultPath)
	defer C.free(unsafe.Pointer(cPath))

	result := C.vault_create_directory(v.handle, cPath)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to create directory"}
	}

	return nil
}

// IsCGOEnabled returns true if CGO is enabled and vault operations are available
func IsCGOEnabled() bool {
	return true
}

// GetVaultID gets the UUID of a vault without opening it
func GetVaultID(path string) (string, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var cUuidOut *C.char
	result := C.vault_get_id(cPath, &cUuidOut)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return "", err
		}
		return "", &VaultError{Code: ErrorCode(result), Message: "Failed to get vault ID"}
	}

	uuidStr := C.GoString(cUuidOut)
	C.vault_free_string(cUuidOut)

	return uuidStr, nil
}

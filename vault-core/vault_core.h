/**
 * Vault Core - C Header for FFI Interface
 * 
 * This header provides C-compatible function declarations for the Rust
 * vault core library, enabling integration with Go, Swift, Kotlin, and
 * other languages that support C FFI.
 */

#ifndef VAULT_CORE_H
#define VAULT_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle types
typedef void* CVaultHandle;
typedef void* CStreamHandle;

// Cipher type enumeration
typedef enum {
    CIPHER_AES256_GCM = 0,
    CIPHER_XCHACHA20_POLY1305 = 1
} CCipherType;

// Error codes
typedef enum {
    ERROR_SUCCESS = 0,
    ERROR_INVALID_PASSWORD = 1,
    ERROR_CORRUPTED_VAULT = 2,
    ERROR_UNSUPPORTED_CIPHER = 3,
    ERROR_FILE_NOT_FOUND = 4,
    ERROR_INSUFFICIENT_SPACE = 5,
    ERROR_PERMISSION_DENIED = 6,
    ERROR_INVALID_ARGUMENT = 7,
    ERROR_INTERNAL_ERROR = 8
} CErrorCode;

// File entry structure
typedef struct {
    char* name;
    uint64_t size;
    int is_dir;
    int64_t mtime;
    uint32_t mode;
} CFileEntry;

// Unlock material structure
typedef struct {
    const char* password;
    const uint8_t* recovery_key;
    size_t recovery_key_len;
} CUnlockMaterial;

// Core vault operations
CVaultHandle vault_create(const char* path, const char* password, CCipherType cipher);
CVaultHandle vault_open(const char* path, const CUnlockMaterial* unlock_material);
int vault_close(CVaultHandle handle);

// Error handling
CErrorCode vault_get_last_error(void);
const char* vault_error_message(CErrorCode error_code);

// X25519 key pair structure for sharing
typedef struct {
    uint8_t public_key[32];
    uint8_t private_key[32];
} CX25519KeyPair;

// Recovery key structure
typedef struct {
    uint8_t key_data[32];
} CRecoveryKey;

// Wrapped master key structure
typedef struct {
    uint8_t* encrypted_key;
    size_t encrypted_key_len;
    uint8_t* nonce;
    size_t nonce_len;
    char* cipher;
    uint8_t* salt;
    size_t salt_len;
    uint32_t memory;
    uint32_t operations;
    uint32_t parallelism;
} CWrappedMasterKey;

// Envelope structure for sharing
typedef struct {
    uint8_t recipient_public_key[32];
    uint8_t* encrypted_key;
    size_t encrypted_key_len;
    uint8_t nonce[24];
} CEnvelope;

// Sharing and envelope encryption functions
int vault_generate_sharing_keypair(CX25519KeyPair* keypair);
int vault_add_sharing_recipient(CVaultHandle handle, const uint8_t* recipient_public_key);
int vault_remove_sharing_recipient(CVaultHandle handle, const uint8_t* recipient_public_key);
int vault_sharing_recipient_count(CVaultHandle handle);
int vault_export_sharing_envelopes(CVaultHandle handle, char** json_out);
int vault_import_sharing_envelopes(CVaultHandle handle, const char* json);
CVaultHandle vault_open_with_recipient_key(const char* path, const uint8_t* recipient_private_key, const char* envelopes_json);

// Password management and recovery functions
int vault_change_password(CVaultHandle handle, const char* old_password, const char* new_password);
int vault_generate_recovery_key(CVaultHandle handle, const char* password, CRecoveryKey* recovery_key_out, CWrappedMasterKey* wrapped_key_out);
int vault_recover_with_key(const char* path, const CRecoveryKey* recovery_key, const CWrappedMasterKey* wrapped_key, const char* new_password);
int vault_recovery_key_to_hex(const CRecoveryKey* recovery_key, char** hex_out);
int vault_recovery_key_from_hex(const char* hex_str, CRecoveryKey* recovery_key_out);

// Memory management functions
void vault_free_string(char* string);
void vault_free_wrapped_key(CWrappedMasterKey* wrapped_key);
void vault_free_envelope(CEnvelope* envelope);

// Future functions (to be implemented in later tasks)
// int vault_list_files(CVaultHandle handle, CFileEntry** entries, size_t* count);
// int vault_read_file(CVaultHandle handle, const char* path, uint8_t** data, size_t* size);
// int vault_write_file(CVaultHandle handle, const char* path, const uint8_t* data, size_t size);
// CStreamHandle vault_open_stream(CVaultHandle handle, const char* path);
// int vault_read_chunk(CStreamHandle stream, uint64_t offset, size_t size, uint8_t* data);

#ifdef __cplusplus
}
#endif

#endif // VAULT_CORE_H
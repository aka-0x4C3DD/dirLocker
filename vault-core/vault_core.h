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
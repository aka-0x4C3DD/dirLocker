# API Documentation

This document outlines the internal interfaces used within **dirLocker**, focusing on the bridge between the Go application layer and the Rust cryptographic core.

## Go Interfaces

### `vault.Vault`
The primary interface for interacting with an open vault.

```go
type Vault interface {
    // File Operations
    ListFiles(path string) ([]FileInfo, error)
    ReadFile(path string) ([]byte, error)
    WriteFile(path string, data []byte) error
    DeleteFile(path string) error
    
    // Management
    Lock() error
    ChangePassword(oldPwd, newPwd string) error
}
```

### `mount.Mounter`
The abstraction for virtual drive mounting mechanisms.

```go
type Mounter interface {
    // Mount mounts the vault at the given mount point (drive letter or directory)
    Mount(mountPoint string, vault *Vault) error
    
    // Unmount unmounts the vault
    Unmount(mountPoint string) error
}
```

## Rust FFI (C-Compatible)

The `vault-core` capability is exposed via C-compatible functions.

### Core Functions
*   `vault_create(path, password)`: Initialize a new vault container.
*   `vault_open(path, password)`: Open an existing vault and return a handle.
*   `vault_close(handle)`: Securely close the vault and zero memory.
*   `vault_generate_recovery_key(handle)`: Generate a 256-bit recovery key.

### File Operations
*   `vault_file_write(handle, path, data, len)`: Encrypt and write data.
*   `vault_file_read(handle, path, out_buffer)`: Decrypt and read data.
*   `vault_file_delete(handle, path)`: Remove file and metadata.

### Error Handling
All FFI functions return a `VaultResult` integer code:
*   `0`: Success
*   `-1`: Generic Error
*   `1`: Invalid Password
*   `2`: IO Error
*   `3`: Crypto Error

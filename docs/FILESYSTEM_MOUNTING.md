# Filesystem Mounting Implementation

This document describes the implementation of Task 18: FUSE filesystem daemon for actual vault mounting.

## Overview

The filesystem mounting system provides the ability to mount encrypted vaults as virtual filesystems on Windows, macOS, and Linux. This allows users to access vault contents through standard file operations using their operating system's native file browser.

## Architecture

### Components

1. **Platform-Specific Filesystem Daemons**
   - `dirlocker-fuse` (Linux/macOS): FUSE-based filesystem daemon
   - `dirlocker-dokany.exe` (Windows): Dokany-based filesystem daemon  
   - `dirlocker-winfsp.exe` (Windows): WinFSP-based filesystem daemon

2. **Mount Manager Infrastructure**
   - `pkg/mount/manager.go`: Cross-platform mount management
   - `pkg/mount/linux.go`: Linux-specific FUSE integration
   - `pkg/mount/darwin.go`: macOS-specific macFUSE integration
   - `pkg/mount/windows.go`: Windows-specific Dokany/WinFSP integration

3. **Filesystem Implementation**
   - `internal/fuse/filesystem.go`: FUSE filesystem operations
   - `internal/dokany/filesystem.go`: Dokany filesystem operations
   - `internal/winfsp/filesystem.go`: WinFSP filesystem operations

## Platform Support

### Linux (FUSE)

**Requirements:**
- FUSE kernel module (`fuse`)
- FUSE development libraries (`libfuse2` or `libfuse3`)
- User must be in `fuse` group or have access to `/dev/fuse`

**Implementation:**
- Uses `bazil.org/fuse` Go library for FUSE operations
- Supports standard FUSE operations: open, read, write, readdir, getattr
- Provides file handle management and caching
- Implements proper Unix filesystem semantics

**Usage:**
```bash
./dirlocker-fuse --vault /path/to/vault.vault --mountpoint /mnt/vault
```

### macOS (macFUSE)

**Requirements:**
- macFUSE framework installed
- System extension approval (Security & Privacy settings)
- Gatekeeper compatibility for distribution

**Implementation:**
- Uses same FUSE implementation as Linux with macOS-specific options
- Supports macOS-specific FUSE options (volname, local, noappledouble)
- Integrates with Finder and native file operations
- Handles macOS permission model

**Usage:**
```bash
./dirlocker-fuse --vault /path/to/vault.vault --mountpoint /Volumes/vault
```

### Windows (Dokany/WinFSP)

**Requirements:**
- Dokany driver OR WinFSP driver installed
- Administrator privileges may be required
- Compatible with Windows 10/11

**Implementation:**
- Dual support for both Dokany and WinFSP
- Automatic driver detection and selection
- Windows-specific filesystem operations
- Drive letter mounting (C:, D:, Z:, etc.)

**Usage:**
```cmd
dirlocker-dokany.exe --vault C:\path\to\vault.vault --drive Z:
dirlocker-winfsp.exe --vault C:\path\to\vault.vault --drive Z:
```

## Filesystem Operations

### Core Operations

1. **File Reading**
   - Streaming read support for large files
   - Chunk-based access for efficient memory usage
   - Random access support for partial file reads

2. **File Writing** (when not read-only)
   - Atomic write operations
   - File handle management
   - Proper synchronization with vault storage

3. **Directory Operations**
   - Directory listing with metadata
   - Nested directory support
   - Directory creation (when not read-only)

4. **Metadata Operations**
   - File attributes (size, timestamps, permissions)
   - Directory attributes
   - Volume information

### File Handle Management

The filesystem maintains file handles for efficient access:

```go
type FileHandle struct {
    ID       uint64
    Path     string
    Data     []byte
    Modified bool
    Offset   int64
}
```

- Unique handle IDs for each open file
- In-memory caching for performance
- Modification tracking for write-back
- Proper cleanup on file close

### Caching Strategy

- File attribute caching with configurable timeout
- Directory entry caching for performance
- Write-through caching for data integrity
- Memory-efficient chunk-based file access

## Integration with Mount Manager

The filesystem daemons integrate with the existing mount manager infrastructure:

### Mount Process

1. **Validation**
   - Check vault accessibility
   - Validate mount point/drive letter
   - Verify required drivers are installed

2. **Daemon Launch**
   - Start appropriate filesystem daemon
   - Pass vault path and mount options
   - Monitor daemon process health

3. **Mount Verification**
   - Wait for mount to become active
   - Verify filesystem accessibility
   - Track mount information

### Unmount Process

1. **Graceful Shutdown**
   - Send termination signal to daemon
   - Wait for clean shutdown
   - Flush any pending operations

2. **Force Unmount**
   - Use platform-specific force unmount
   - Clean up stale mount points
   - Terminate daemon process if needed

3. **Cleanup**
   - Remove mount tracking
   - Clear cached data
   - Update mount registry

## Error Handling

### Mount Errors

- **Driver Not Found**: Required FUSE/Dokany/WinFSP not installed
- **Permission Denied**: Insufficient privileges for mounting
- **Mount Point In Use**: Target location already mounted
- **Timeout**: Mount operation took too long
- **Invalid Options**: Malformed mount parameters

### Runtime Errors

- **File Not Found**: Requested file doesn't exist in vault
- **Access Denied**: Read-only filesystem write attempt
- **I/O Error**: Vault read/write operation failed
- **Handle Invalid**: File handle no longer valid

### Recovery Mechanisms

- Automatic retry for transient errors
- Graceful degradation for partial failures
- Mount point cleanup on daemon crash
- Stale mount detection and cleanup

## Performance Considerations

### Optimization Strategies

1. **Caching**
   - File attribute caching reduces vault queries
   - Directory listing caching improves browsing
   - Configurable cache timeouts

2. **Streaming**
   - Large file streaming prevents memory exhaustion
   - Chunk-based access for random reads
   - Lazy loading of file content

3. **Concurrency**
   - Multiple file handles supported
   - Concurrent read operations
   - Thread-safe handle management

### Memory Management

- Bounded file handle cache
- Automatic cleanup of unused handles
- Memory-efficient chunk processing
- Proper resource cleanup on unmount

## Security Considerations

### Access Control

- Vault password required for daemon startup
- No password storage in daemon process
- Proper file permission mapping
- User-space filesystem isolation

### Data Protection

- Encrypted vault content never written to disk unencrypted
- Memory clearing on file handle close
- Secure random number generation
- Protection against timing attacks

## Testing

### Unit Tests

- Filesystem operation tests
- File handle management tests
- Error condition testing
- Mock vault integration

### Integration Tests

- End-to-end mount/unmount testing
- Cross-platform compatibility testing
- Performance benchmarking
- Error recovery testing

### Platform-Specific Tests

- FUSE operation validation (Linux/macOS)
- Dokany/WinFSP integration testing (Windows)
- Driver availability checking
- Permission model testing

## Build and Deployment

### Build Requirements

- Go 1.24+ with CGO enabled
- Platform-specific dependencies:
  - Linux: FUSE development headers
  - macOS: macFUSE framework
  - Windows: MinGW toolchain

### Build Commands

```bash
# Linux/macOS
./build-fuse.sh

# Windows
build-fuse.bat
```

### Distribution

- Standalone daemon binaries
- No additional runtime dependencies
- Platform-specific packaging
- Driver installation documentation

## Troubleshooting

### Common Issues

1. **Mount Fails on Linux**
   - Install FUSE: `sudo apt install fuse libfuse2`
   - Add user to fuse group: `sudo usermod -a -G fuse $USER`
   - Load fuse module: `sudo modprobe fuse`

2. **Mount Fails on macOS**
   - Install macFUSE from official website
   - Allow system extension in Security & Privacy
   - Check mount point permissions

3. **Mount Fails on Windows**
   - Install Dokany or WinFSP driver
   - Run as Administrator if required
   - Check drive letter availability

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Linux/macOS
./dirlocker-fuse --vault vault.vault --mountpoint /mnt/vault --debug

# Windows
dirlocker-dokany.exe --vault vault.vault --drive Z: --debug
```

## Future Enhancements

### Planned Features

1. **Performance Improvements**
   - Asynchronous I/O operations
   - Advanced caching strategies
   - Connection pooling

2. **Feature Additions**
   - Extended attribute support
   - File locking mechanisms
   - Notification system integration

3. **Platform Enhancements**
   - Windows Shell integration
   - macOS Spotlight indexing
   - Linux desktop integration

### Compatibility

- Backward compatibility with existing vault formats
- Forward compatibility with future vault versions
- Cross-platform vault sharing support

## Conclusion

The filesystem mounting implementation provides a robust, cross-platform solution for accessing encrypted vault contents through native filesystem operations. The modular architecture supports multiple filesystem drivers while maintaining consistent behavior across platforms.

The implementation successfully addresses all requirements from Task 18:
- ✅ Standalone filesystem daemon binaries
- ✅ Platform-specific driver integration
- ✅ Core filesystem operations
- ✅ Vault-to-filesystem translation layer
- ✅ File handle management and caching
- ✅ Proper filesystem semantics
- ✅ Mount manager integration
- ✅ Comprehensive testing suite
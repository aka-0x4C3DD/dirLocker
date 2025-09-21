 # Implementation Plan

- [x] 1. Set up project structure and core Rust cryptographic library





  - Create Rust library project with proper Cargo.toml configuration
  - Set up FFI exports and C-compatible interface definitions
  - Configure dependencies: libsodium, aes-gcm, argon2, hkdf, x25519-dalek
  - Implement basic vault handle and error code structures
  - _Requirements: 1.1, 1.3, 2.1, 2.2, 2.3, 15.5_

- [x] 2. Implement vault container format and parsing





  - Create vault file format structures matching the specification (Magic "VLT1", Version, HeaderLen, HeaderJSON)
  - Implement vault creation with proper header generation and JSON serialization
  - Write vault opening and header validation logic
  - Add version compatibility checking and algorithm identifier parsing
  - Create unit tests with cross-platform compatibility test vectors
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 3. Implement key derivation and cryptographic operations





  - Implement Argon2id KDF with configurable parameters (memory=64MB+, operations=3, parallelism=1)
  - Create HKDF-based subkey derivation for file_encryption_key, filename_key, and mac_key
  - Implement AES-256-GCM encryption/decryption with hardware acceleration detection
  - Implement XChaCha20-Poly1305 encryption/decryption using libsodium
  - Add CSPRNG integration for secure random number generation
  - Create comprehensive unit tests for all cryptographic operations
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.4, 15.1, 15.2_

- [x] 4. Implement file table encryption and metadata protection





  - Create encrypted file table structure with filename encryption using deterministic AEAD
  - Implement directory structure and metadata encryption (sizes, timestamps, permissions)
  - Add file table serialization/deserialization with header AAD authentication
  - Create filename encryption system using dedicated filename_key
  - Write unit tests for metadata protection and filename encryption
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 5. Implement file chunking and streaming operations





  - Create configurable file chunking system (default 4MB chunks)
  - Implement individual chunk AEAD encryption with unique nonces
  - Add chunk mapping storage in encrypted file table
  - Create streaming API for reading file ranges without full memory loading
  - Implement random access functionality by reading relevant chunks only
  - Write performance tests for large file handling and streaming
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 6. Implement secure sharing and envelope encryption











  - Create X25519 key pair generation and management
  - Implement envelope encryption using X25519 + AEAD for per-recipient access
  - Add multi-recipient support with individual envelope storage
  - Create recipient management functions (add/remove recipients)
  - Implement envelope import/export functionality
  - Write unit tests for sharing scenarios and envelope operations
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 7. Implement password management and recovery systems







  - Create master key wrapping/unwrapping system for password changes
  - Implement recovery key generation (32-byte random data) and master key unwrapping
  - Add password change functionality that re-wraps master key without re-encrypting chunks
  - Create algorithm rotation support with background re-encryption jobs
  - Implement secure key storage and memory management
  - Write unit tests for password change and recovery scenarios
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 15.1, 15.4_

- [x] 7.2. Complete C FFI interface and header file integration







  - Update vault_core.h header file with missing recovery key structures (CRecoveryKey, CWrappedMasterKey)
  - Add missing recovery key FFI functions (vault_generate_recovery_key, vault_recovery_key_to_hex, vault_recovery_key_from_hex, vault_recover_with_key)
  - Update header file with missing sharing structures (CX25519KeyPair, CEnvelope)
  - Add missing sharing FFI functions (vault_generate_sharing_keypair, vault_add_sharing_recipient, vault_remove_sharing_recipient, vault_sharing_recipient_count, vault_export_sharing_envelopes, vault_import_sharing_envelopes, vault_open_with_recipient_key)
  - Add missing password management functions (vault_change_password)
  - Add missing utility functions (vault_free_string, vault_free_wrapped_key, vault_free_envelope)
  - Export all FFI functions from Rust library with proper C ABI
  - Update Go CGO bindings to use new FFI functions
  - Test CGO integration to ensure it builds and links correctly
  - Write integration tests for all new FFI functions
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 7.1. Fix vault file format and chunk storage architecture






  - Redesign vault file layout to prevent file table and chunk data conflicts
  - Implement proper space management with dynamic file table positioning
  - Fix chunk offset calculation to account for actual file table size and location
  - Add atomic file operations to prevent corruption during file table updates
  - Implement proper file table versioning and backward compatibility
  - Create comprehensive integration tests for file persistence after write operations
  - Resolve AAD consistency issues in file table encryption/decryption
  - Add file defragmentation and space reclamation functionality
  - _Requirements: 6.1, 6.2, 6.3, 3.1, 3.2, 9.1_

- [x] 8. Implement vault integrity and repair mechanisms





  - Create atomic write operations using temp-file-then-rename pattern
  - Implement chunk integrity validation using AEAD tags
  - Add vault repair functionality that reconstructs file table from valid chunks
  - Create partial recovery system for corrupted vaults
  - Implement integrity checking and validation functions
  - Write unit tests for corruption scenarios and repair operations
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [x] 9. Set up Go application structure and core library integration







  - Create Go project structure with CLI and GUI applications
  - Set up CGO bindings to Rust core library with proper error handling
  - Implement VaultManager wrapper around core library FFI calls
  - Create configuration management system with JSON serialization
  - Add logging system that never logs sensitive data
  - Write integration tests between Go layer and Rust core
  - _Requirements: 11.1, 11.4, 15.3, 15.5_

- [x] 10. Implement CLI application with comprehensive vault operations









  - determine what all mcp servers are available and will be useful for the task (like filesystem, everyhting, fetch, rust-mcp-server, go-dev-mcp, awslabs-core) and use them throughout the task, use steering files to understand stuff
  - Create CLI using Cobra framework with create, open, list, mount, extract, push, share, change-password, repair commands
  - Implement vault creation CLI with cipher choice and KDF parameter specification
  - Add vault mounting/unmounting commands with platform detection
  - Create sharing commands with envelope export/import functionality
  - Implement repair and integrity checking CLI commands
  - Write CLI integration tests and help documentation
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [x] 11. Implement file hiding system for Windows and Unix platforms






  - Create FileHider interface with Hide, Unhide, List, and IsHidden methods
  - Implement WindowsFileHider using %APPDATA%\dirLocker hidden directory and Windows file attributes
  - Implement UnixFileHider using ~/.dirlocker hidden directory and extended attributes
  - Create encrypted registry system for tracking hidden files with checksums
  - Add file integrity verification during hide/unhide operations
  - Write comprehensive tests for file hiding on each platform
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

- [ ] 12. Implement icon management system
  - Create IconManager for detecting .ico files in application directory
  - Implement custom icon application with fallback to default icon
  - Add multiple icon detection with alphabetical selection and warning logging
  - Create icon validation and corruption handling with error logging
  - Implement icon change detection and application restart notification
  - Write unit tests for icon detection and application scenarios
  - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

- [ ] 13. Implement Qt-based GUI application
  - Create Qt GUI application using therecipe/qt with main window and vault browser
  - Implement vault creation/opening dialogs with cipher selection
  - Add file browser with tree view showing vault contents
  - Create file hiding interface with visual indicators for hidden files
  - Implement mount/unmount functionality with platform-specific integration
  - Add settings dialog for configuration management
  - Write GUI integration tests and user workflow tests
  - _Requirements: 4.5, 12.5_

- [ ] 14. Implement desktop filesystem mounting
  - Create Windows mounting using Dokany/WinFSP with UAC elevation handling
  - Implement macOS mounting using macFUSE with Gatekeeper compatibility
  - Add Linux mounting using FUSE with distribution-specific considerations
  - Create mount point management and cleanup on unmount
  - Implement secure memory clearing when unmounting vaults
  - Write platform-specific mounting tests and error handling
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ] 15. Implement plausible deniability features
  - Create multiple file table support with separate password encryption
  - Implement indistinguishable file table storage in same container format
  - Add decoy file table creation and management
  - Create metadata wiping functionality for enhanced deniability
  - Implement clear documentation of deniability limitations
  - Write unit tests for multiple file table scenarios
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ] 16. Set up automated build and packaging system
  - Create cross-compilation setup for Windows, macOS, and Linux desktop applications
  - Implement MSI package generation for Windows with proper metadata and dependencies
  - Add DMG package generation for macOS with code signing and notarization
  - Create DEB package generation for Linux with distribution-specific metadata
  - Set up build automation with version information and checksums
  - Implement package integrity verification and testing
  - _Requirements: 14.1, 14.2, 14.3, 14.6, 14.7_

- [ ] 17. Implement iOS mobile application
  - Create iOS Swift application with File Provider extension
  - Integrate Rust core library via C FFI with proper memory management
  - Implement Files app integration using File Provider extension
  - Add Touch ID/Face ID authentication support
  - Create in-app file browser for vault contents
  - Set up IPA package generation for App Store distribution
  - _Requirements: 5.1, 5.3, 5.4, 5.5, 14.5_

- [ ] 18. Implement Android mobile application
  - Create Android Kotlin application with DocumentProvider implementation
  - Integrate Rust core library via JNI with proper lifecycle management
  - Implement Storage Access Framework (SAF) integration
  - Add biometric authentication support
  - Create Material Design UI for vault browsing
  - Set up APK/AAB package generation for Play Store distribution
  - _Requirements: 5.2, 5.3, 5.4, 5.5, 14.4_

- [ ] 19. Implement comprehensive testing and security validation
  - Create cross-platform compatibility test suite with test vectors
  - Implement security testing for memory hygiene and key material protection
  - Add performance testing for large vaults and concurrent access
  - Create fuzzing tests for vault file format parsing
  - Implement end-to-end workflow testing across all platforms
  - Add cryptographic validation tests with known test vectors
  - _Requirements: 15.1, 15.2, 15.3, 15.5_

- [ ] 20. Finalize dirLocker documentation and distribution preparation
  - Create comprehensive user documentation and security guidelines for dirLocker
  - Implement final integration testing across all platforms and features
  - Set up distribution channels and update mechanisms for dirLocker
  - Create security audit documentation and threat model validation
  - Finalize code signing, notarization, and store submission processes
  - Prepare dirLocker release packages with proper versioning and checksums
  - _Requirements: 14.6, 14.7, 15.5_
//! FFI (Foreign Function Interface) exports for C compatibility
//!
//! This module provides C-compatible functions that can be called from Go, Swift,
//! Kotlin, and other languages that support C FFI.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

use crate::error::VaultErrorCode;
use crate::vault::Vault;

/// Opaque handle for vault instances
pub type CVaultHandle = *mut Vault;

/// Cipher type enumeration for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CCipherType {
    Aes256Gcm = 0,
    XChaCha20Poly1305 = 1,
}

/// Error codes for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CErrorCode {
    Success = 0,
    InvalidPassword = 1,
    CorruptedVault = 2,
    UnsupportedCipher = 3,
    FileNotFound = 4,
    InsufficientSpace = 5,
    PermissionDenied = 6,
    InvalidArgument = 7,
    InternalError = 8,
}

impl From<VaultErrorCode> for CErrorCode {
    fn from(code: VaultErrorCode) -> Self {
        match code {
            VaultErrorCode::InvalidPassword => CErrorCode::InvalidPassword,
            VaultErrorCode::CorruptedVault => CErrorCode::CorruptedVault,
            VaultErrorCode::UnsupportedCipher => CErrorCode::UnsupportedCipher,
            VaultErrorCode::FileNotFound => CErrorCode::FileNotFound,
            VaultErrorCode::InsufficientSpace => CErrorCode::InsufficientSpace,
            VaultErrorCode::PermissionDenied => CErrorCode::PermissionDenied,
            VaultErrorCode::InvalidArgument => CErrorCode::InvalidArgument,
            VaultErrorCode::InternalError => CErrorCode::InternalError,
        }
    }
}

/// File entry structure for FFI
#[repr(C)]
pub struct CFileEntry {
    pub name: *mut c_char,
    pub size: u64,
    pub is_dir: c_int,
    pub mtime: i64,
    pub mode: c_uint,
}

/// Stream handle for reading file chunks
pub type CStreamHandle = *mut std::fs::File;

/// Unlock material structure for vault opening
#[repr(C)]
pub struct CUnlockMaterial {
    pub password: *const c_char,
    pub recovery_key: *const u8,
    pub recovery_key_len: usize,
}

/// X25519 key pair structure for FFI
#[repr(C)]
pub struct CX25519KeyPair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

/// Envelope structure for FFI
#[repr(C)]
pub struct CEnvelope {
    pub recipient_public_key: [u8; 32],
    pub encrypted_key: *mut u8,
    pub encrypted_key_len: usize,
    pub nonce: [u8; 24],
}

/// Create a new vault container
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `password` must be a valid null-terminated C string
/// - Returns null handle on failure, check last error
#[no_mangle]
pub extern "C" fn vault_create(
    path: *const c_char,
    password: *const c_char,
    cipher: CCipherType,
) -> CVaultHandle {
    if path.is_null() || password.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return ptr::null_mut();
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    match Vault::create(path_str, password_str, cipher.into()) {
        Ok(vault) => {
            set_last_error(CErrorCode::Success);
            Box::into_raw(Box::new(vault))
        }
        Err(e) => {
            set_last_error(e.code().into());
            ptr::null_mut()
        }
    }
}

/// Open an existing vault container
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `unlock_material` must point to valid unlock material
/// - Returns null handle on failure, check last error
#[no_mangle]
pub extern "C" fn vault_open(
    path: *const c_char,
    unlock_material: *const CUnlockMaterial,
) -> CVaultHandle {
    if path.is_null() || unlock_material.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return ptr::null_mut();
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    let unlock = unsafe { &*unlock_material };

    // For now, only support password-based unlocking
    if unlock.password.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return ptr::null_mut();
    }

    let password_str = match unsafe { CStr::from_ptr(unlock.password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    match Vault::open(path_str, password_str) {
        Ok(vault) => {
            set_last_error(CErrorCode::Success);
            Box::into_raw(Box::new(vault))
        }
        Err(e) => {
            set_last_error(e.code().into());
            ptr::null_mut()
        }
    }
}

/// Close a vault and free its resources
///
/// # Safety
/// - `handle` must be a valid vault handle returned from vault_create or vault_open
/// - Handle becomes invalid after this call
#[no_mangle]
pub extern "C" fn vault_close(handle: CVaultHandle) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    unsafe {
        let _vault = Box::from_raw(handle);
        // Vault will be dropped here, cleaning up resources
    }

    set_last_error(CErrorCode::Success);
    CErrorCode::Success as c_int
}

/// Get the last error code from the most recent operation
#[no_mangle]
pub extern "C" fn vault_get_last_error() -> CErrorCode {
    get_last_error()
}

/// Get a human-readable error message for an error code
///
/// # Safety
/// - Returns a static string that doesn't need to be freed
#[no_mangle]
pub extern "C" fn vault_error_message(error_code: CErrorCode) -> *const c_char {
    let message = match error_code {
        CErrorCode::Success => "Success\0",
        CErrorCode::InvalidPassword => "Invalid password or corrupted vault\0",
        CErrorCode::CorruptedVault => "Vault file appears to be corrupted\0",
        CErrorCode::UnsupportedCipher => "Unsupported cipher algorithm\0",
        CErrorCode::FileNotFound => "File not found in vault\0",
        CErrorCode::InsufficientSpace => "Insufficient disk space\0",
        CErrorCode::PermissionDenied => "Permission denied\0",
        CErrorCode::InvalidArgument => "Invalid argument provided\0",
        CErrorCode::InternalError => "Internal error occurred\0",
    };

    message.as_ptr() as *const c_char
}

// Thread-local storage for last error
thread_local! {
    static LAST_ERROR: std::cell::Cell<CErrorCode> = std::cell::Cell::new(CErrorCode::Success);
}

fn set_last_error(error: CErrorCode) {
    LAST_ERROR.with(|e| e.set(error));
}

fn get_last_error() -> CErrorCode {
    LAST_ERROR.with(|e| e.get())
}

impl From<CCipherType> for crate::crypto::CipherType {
    fn from(cipher: CCipherType) -> Self {
        match cipher {
            CCipherType::Aes256Gcm => crate::crypto::CipherType::Aes256Gcm,
            CCipherType::XChaCha20Poly1305 => crate::crypto::CipherType::XChaCha20Poly1305,
        }
    }
}

// Sharing and envelope encryption FFI functions

/// Generate a new X25519 key pair for sharing
///
/// # Safety
/// - `keypair` must point to valid memory for CX25519KeyPair
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_generate_sharing_keypair(keypair: *mut CX25519KeyPair) -> c_int {
    if keypair.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    match crate::vault::Vault::generate_sharing_keypair() {
        Ok(kp) => {
            unsafe {
                (*keypair).public_key = *kp.public_key_bytes();
                (*keypair).private_key = *kp.private_key_bytes();
            }
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Add a recipient for secure sharing
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `recipient_public_key` must point to 32 bytes
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_add_sharing_recipient(
    handle: CVaultHandle,
    recipient_public_key: *const u8,
) -> c_int {
    if handle.is_null() || recipient_public_key.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let public_key_slice = unsafe { std::slice::from_raw_parts(recipient_public_key, 32) };

    let public_key: [u8; 32] = match public_key_slice.try_into() {
        Ok(key) => key,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.add_sharing_recipient(public_key) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Remove a recipient from secure sharing
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `recipient_public_key` must point to 32 bytes
/// - Returns 1 if removed, 0 if not found, negative on error
#[no_mangle]
pub extern "C" fn vault_remove_sharing_recipient(
    handle: CVaultHandle,
    recipient_public_key: *const u8,
) -> c_int {
    if handle.is_null() || recipient_public_key.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let public_key_slice = unsafe { std::slice::from_raw_parts(recipient_public_key, 32) };

    let public_key: [u8; 32] = match public_key_slice.try_into() {
        Ok(key) => key,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.remove_sharing_recipient(&public_key) {
        Ok(removed) => {
            set_last_error(CErrorCode::Success);
            if removed {
                1
            } else {
                0
            }
        }
        Err(e) => {
            set_last_error(e.code().into());
            -(e.code() as c_int)
        }
    }
}

/// Get the number of sharing recipients
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - Returns recipient count on success, negative error code on failure
#[no_mangle]
pub extern "C" fn vault_sharing_recipient_count(handle: CVaultHandle) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    match vault.sharing_recipient_count() {
        Ok(count) => {
            set_last_error(CErrorCode::Success);
            count as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            -(e.code() as c_int)
        }
    }
}

/// Export sharing envelopes as JSON string
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `json_out` will be set to allocated string (must be freed with vault_free_string)
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_export_sharing_envelopes(
    handle: CVaultHandle,
    json_out: *mut *mut c_char,
) -> c_int {
    if handle.is_null() || json_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    match vault.export_sharing_envelopes() {
        Ok(json) => {
            let c_string = match std::ffi::CString::new(json) {
                Ok(s) => s,
                Err(_) => {
                    set_last_error(CErrorCode::InternalError);
                    return CErrorCode::InternalError as c_int;
                }
            };

            unsafe {
                *json_out = c_string.into_raw();
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Import sharing envelopes from JSON string
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `json` must be a valid null-terminated C string
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_import_sharing_envelopes(
    handle: CVaultHandle,
    json: *const c_char,
) -> c_int {
    if handle.is_null() || json.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let json_str = match unsafe { CStr::from_ptr(json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.import_sharing_envelopes(json_str) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Open vault using recipient's private key for shared access
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `recipient_private_key` must point to 32 bytes
/// - `envelopes_json` must be a valid null-terminated C string
/// - Returns null handle on failure, check last error
#[no_mangle]
pub extern "C" fn vault_open_with_recipient_key(
    path: *const c_char,
    recipient_private_key: *const u8,
    envelopes_json: *const c_char,
) -> CVaultHandle {
    if path.is_null() || recipient_private_key.is_null() || envelopes_json.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return ptr::null_mut();
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    let json_str = match unsafe { CStr::from_ptr(envelopes_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    let private_key_slice = unsafe { std::slice::from_raw_parts(recipient_private_key, 32) };
    let private_key: [u8; 32] = match private_key_slice.try_into() {
        Ok(key) => key,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    match crate::vault::Vault::open_with_recipient_key(path_str, &private_key, json_str) {
        Ok(vault) => {
            set_last_error(CErrorCode::Success);
            Box::into_raw(Box::new(vault))
        }
        Err(e) => {
            set_last_error(e.code().into());
            ptr::null_mut()
        }
    }
}

/// Free a string allocated by the vault library
///
/// # Safety
/// - `string` must be a string previously allocated by vault library functions
/// - String becomes invalid after this call
#[no_mangle]
pub extern "C" fn vault_free_string(string: *mut c_char) {
    if !string.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(string);
        }
    }
}
// Password management and recovery FFI functions

/// Recovery key structure for FFI
#[repr(C)]
pub struct CRecoveryKey {
    pub key_data: [u8; 32],
}

/// Wrapped master key structure for FFI
#[repr(C)]
pub struct CWrappedMasterKey {
    pub encrypted_key: *mut u8,
    pub encrypted_key_len: usize,
    pub nonce: *mut u8,
    pub nonce_len: usize,
    pub cipher: *mut c_char,
    pub salt: *mut u8,
    pub salt_len: usize,
    pub memory: u32,
    pub operations: u32,
    pub parallelism: u32,
}

/// Change vault password without re-encrypting chunks
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `old_password` and `new_password` must be valid null-terminated C strings
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_change_password(
    handle: CVaultHandle,
    old_password: *const c_char,
    new_password: *const c_char,
) -> c_int {
    if handle.is_null() || old_password.is_null() || new_password.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    let old_pass_str = match unsafe { CStr::from_ptr(old_password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    let new_pass_str = match unsafe { CStr::from_ptr(new_password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.change_password(old_pass_str, new_pass_str) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Generate a recovery key for the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `password` must be a valid null-terminated C string
/// - `recovery_key_out` must point to valid CRecoveryKey memory
/// - `wrapped_key_out` must point to valid CWrappedMasterKey memory
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_generate_recovery_key(
    handle: CVaultHandle,
    password: *const c_char,
    recovery_key_out: *mut CRecoveryKey,
    wrapped_key_out: *mut CWrappedMasterKey,
) -> c_int {
    if handle.is_null()
        || password.is_null()
        || recovery_key_out.is_null()
        || wrapped_key_out.is_null()
    {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.generate_recovery_key(password_str) {
        Ok((recovery_key, wrapped_key)) => {
            unsafe {
                // Copy recovery key
                (*recovery_key_out).key_data = *recovery_key.as_bytes();

                // Allocate and copy wrapped key data
                let encrypted_key_ptr = libc::malloc(wrapped_key.encrypted_key.len()) as *mut u8;
                if encrypted_key_ptr.is_null() {
                    set_last_error(CErrorCode::InternalError);
                    return CErrorCode::InternalError as c_int;
                }
                std::ptr::copy_nonoverlapping(
                    wrapped_key.encrypted_key.as_ptr(),
                    encrypted_key_ptr,
                    wrapped_key.encrypted_key.len(),
                );

                let nonce_ptr = libc::malloc(wrapped_key.nonce.len()) as *mut u8;
                if nonce_ptr.is_null() {
                    libc::free(encrypted_key_ptr as *mut libc::c_void);
                    set_last_error(CErrorCode::InternalError);
                    return CErrorCode::InternalError as c_int;
                }
                std::ptr::copy_nonoverlapping(
                    wrapped_key.nonce.as_ptr(),
                    nonce_ptr,
                    wrapped_key.nonce.len(),
                );

                let salt_ptr = libc::malloc(wrapped_key.kdf_params.salt.len()) as *mut u8;
                if salt_ptr.is_null() {
                    libc::free(encrypted_key_ptr as *mut libc::c_void);
                    libc::free(nonce_ptr as *mut libc::c_void);
                    set_last_error(CErrorCode::InternalError);
                    return CErrorCode::InternalError as c_int;
                }
                std::ptr::copy_nonoverlapping(
                    wrapped_key.kdf_params.salt.as_ptr(),
                    salt_ptr,
                    wrapped_key.kdf_params.salt.len(),
                );

                let cipher_cstring = match std::ffi::CString::new(wrapped_key.cipher) {
                    Ok(s) => s,
                    Err(_) => {
                        libc::free(encrypted_key_ptr as *mut libc::c_void);
                        libc::free(nonce_ptr as *mut libc::c_void);
                        libc::free(salt_ptr as *mut libc::c_void);
                        set_last_error(CErrorCode::InternalError);
                        return CErrorCode::InternalError as c_int;
                    }
                };

                (*wrapped_key_out).encrypted_key = encrypted_key_ptr;
                (*wrapped_key_out).encrypted_key_len = wrapped_key.encrypted_key.len();
                (*wrapped_key_out).nonce = nonce_ptr;
                (*wrapped_key_out).nonce_len = wrapped_key.nonce.len();
                (*wrapped_key_out).cipher = cipher_cstring.into_raw();
                (*wrapped_key_out).salt = salt_ptr;
                (*wrapped_key_out).salt_len = wrapped_key.kdf_params.salt.len();
                (*wrapped_key_out).memory = wrapped_key.kdf_params.memory;
                (*wrapped_key_out).operations = wrapped_key.kdf_params.operations;
                (*wrapped_key_out).parallelism = wrapped_key.kdf_params.parallelism;
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

// Biometrics and Secure Storage FFI

/// Store a credential in the system secure store (keyring)
///
/// # Safety
/// - `service`, `user`, `password` must be valid null-terminated C strings
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_secure_store(
    service: *const c_char,
    user: *const c_char,
    password: *const c_char,
) -> c_int {
    if service.is_null() || user.is_null() || password.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let service_str = match unsafe { CStr::from_ptr(service) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };
    let user_str = match unsafe { CStr::from_ptr(user) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };
    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match crate::biometrics::save_credential(service_str, user_str, password_str) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Retrieve a credential from the system secure store
///
/// # Safety
/// - `service`, `user` must be valid C strings
/// - `password_out` will be allocated, must be freed with vault_free_string
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_secure_get(
    service: *const c_char,
    user: *const c_char,
    password_out: *mut *mut c_char,
) -> c_int {
    if service.is_null() || user.is_null() || password_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let service_str = match unsafe { CStr::from_ptr(service) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };
    let user_str = match unsafe { CStr::from_ptr(user) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match crate::biometrics::get_credential(service_str, user_str) {
        Ok(pass) => {
            let c_string = match std::ffi::CString::new(pass) {
                Ok(s) => s,
                Err(_) => {
                    set_last_error(CErrorCode::InternalError);
                    return CErrorCode::InternalError as c_int;
                }
            };
            unsafe {
                *password_out = c_string.into_raw();
            }
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Delete a credential from the system secure store
///
/// # Safety
/// - `service`, `user` must be valid C strings
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_secure_delete(service: *const c_char, user: *const c_char) -> c_int {
    if service.is_null() || user.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let service_str = match unsafe { CStr::from_ptr(service) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };
    let user_str = match unsafe { CStr::from_ptr(user) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match crate::biometrics::delete_credential(service_str, user_str) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Recover vault access using recovery key
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `recovery_key` must point to valid CRecoveryKey
/// - `wrapped_key` must point to valid CWrappedMasterKey
/// - `new_password` must be a valid null-terminated C string
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_recover_with_key(
    path: *const c_char,
    recovery_key: *const CRecoveryKey,
    wrapped_key: *const CWrappedMasterKey,
    new_password: *const c_char,
) -> c_int {
    if path.is_null() || recovery_key.is_null() || wrapped_key.is_null() || new_password.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    let new_password_str = match unsafe { CStr::from_ptr(new_password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    // Convert C structures to Rust structures
    let rust_recovery_key =
        match crate::password::RecoveryKey::from_bytes(unsafe { &(*recovery_key).key_data }) {
            Ok(key) => key,
            Err(_) => {
                set_last_error(CErrorCode::InvalidArgument);
                return CErrorCode::InvalidArgument as c_int;
            }
        };

    let wrapped_key_data = unsafe { &*wrapped_key };
    let encrypted_key = unsafe {
        std::slice::from_raw_parts(
            wrapped_key_data.encrypted_key,
            wrapped_key_data.encrypted_key_len,
        )
    }
    .to_vec();
    let nonce =
        unsafe { std::slice::from_raw_parts(wrapped_key_data.nonce, wrapped_key_data.nonce_len) }
            .to_vec();
    let salt =
        unsafe { std::slice::from_raw_parts(wrapped_key_data.salt, wrapped_key_data.salt_len) }
            .to_vec();
    let cipher = match unsafe { CStr::from_ptr(wrapped_key_data.cipher) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    let rust_wrapped_key = crate::password::WrappedMasterKey {
        encrypted_key,
        nonce,
        cipher,
        kdf_params: crate::format::KdfParams {
            salt,
            memory: wrapped_key_data.memory,
            operations: wrapped_key_data.operations,
            parallelism: wrapped_key_data.parallelism,
        },
    };

    match crate::vault::Vault::recover_with_key(
        path_str,
        &rust_recovery_key,
        &rust_wrapped_key,
        new_password_str,
    ) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Free a wrapped master key structure
///
/// # Safety
/// - `wrapped_key` must be a CWrappedMasterKey previously allocated by vault functions
/// - Structure becomes invalid after this call
#[no_mangle]
pub extern "C" fn vault_free_wrapped_key(wrapped_key: *mut CWrappedMasterKey) {
    if wrapped_key.is_null() {
        return;
    }

    unsafe {
        let key_data = &mut *wrapped_key;

        if !key_data.encrypted_key.is_null() {
            libc::free(key_data.encrypted_key as *mut libc::c_void);
        }

        if !key_data.nonce.is_null() {
            libc::free(key_data.nonce as *mut libc::c_void);
        }

        if !key_data.salt.is_null() {
            libc::free(key_data.salt as *mut libc::c_void);
        }

        if !key_data.cipher.is_null() {
            let _ = std::ffi::CString::from_raw(key_data.cipher);
        }
    }
}

/// Rotate vault to new encryption algorithm
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `password` must be a valid null-terminated C string
/// - `progress_callback` can be null or point to valid callback function
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_rotate_algorithm(
    handle: CVaultHandle,
    password: *const c_char,
    new_cipher: CCipherType,
    progress_callback: Option<extern "C" fn(processed: usize, total: usize)>,
) -> c_int {
    if handle.is_null() || password.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    let callback: Option<Box<dyn Fn(usize, usize) + Send>> = progress_callback.map(|cb| {
        Box::new(move |processed, total| {
            cb(processed, total);
        }) as Box<dyn Fn(usize, usize) + Send>
    });

    match vault.rotate_algorithm(password_str, new_cipher.into(), callback) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Convert recovery key to hex string
///
/// # Safety
/// - `recovery_key` must point to valid CRecoveryKey
/// - `hex_out` will be set to allocated string (must be freed with vault_free_string)
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_recovery_key_to_hex(
    recovery_key: *const CRecoveryKey,
    hex_out: *mut *mut c_char,
) -> c_int {
    if recovery_key.is_null() || hex_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let rust_recovery_key =
        match crate::password::RecoveryKey::from_bytes(unsafe { &(*recovery_key).key_data }) {
            Ok(key) => key,
            Err(_) => {
                set_last_error(CErrorCode::InvalidArgument);
                return CErrorCode::InvalidArgument as c_int;
            }
        };

    let hex_string = rust_recovery_key.to_hex();

    let c_string = match std::ffi::CString::new(hex_string) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InternalError);
            return CErrorCode::InternalError as c_int;
        }
    };

    unsafe {
        *hex_out = c_string.into_raw();
    }

    set_last_error(CErrorCode::Success);
    CErrorCode::Success as c_int
}

/// Create recovery key from hex string
///
/// # Safety
/// - `hex_str` must be a valid null-terminated C string
/// - `recovery_key_out` must point to valid CRecoveryKey memory
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_recovery_key_from_hex(
    hex_str: *const c_char,
    recovery_key_out: *mut CRecoveryKey,
) -> c_int {
    if hex_str.is_null() || recovery_key_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let hex_string = match unsafe { CStr::from_ptr(hex_str) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match crate::password::RecoveryKey::from_hex(hex_string) {
        Ok(recovery_key) => {
            unsafe {
                (*recovery_key_out).key_data = *recovery_key.as_bytes();
            }
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            CErrorCode::InvalidArgument as c_int
        }
    }
}

// File operations FFI functions

/// List all files and directories in the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `entries` will be set to allocated array (must be freed with vault_free_file_entries)
/// - `count` will be set to number of entries
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_list_files(
    handle: CVaultHandle,
    entries: *mut *mut CFileEntry,
    count: *mut usize,
) -> c_int {
    if handle.is_null() || entries.is_null() || count.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    match vault.list_files() {
        Ok(file_list) => {
            let entry_count = file_list.len();

            if entry_count == 0 {
                unsafe {
                    *entries = ptr::null_mut();
                    *count = 0;
                }
                set_last_error(CErrorCode::Success);
                return CErrorCode::Success as c_int;
            }

            // Allocate array of CFileEntry
            let entries_ptr = unsafe {
                libc::malloc(entry_count * std::mem::size_of::<CFileEntry>()) as *mut CFileEntry
            };

            if entries_ptr.is_null() {
                set_last_error(CErrorCode::InternalError);
                return CErrorCode::InternalError as c_int;
            }

            // Fill the array
            for (i, file_info) in file_list.iter().enumerate() {
                let name_cstring = match std::ffi::CString::new(file_info.name.clone()) {
                    Ok(s) => s,
                    Err(_) => {
                        // Clean up allocated memory
                        unsafe {
                            for j in 0..i {
                                let entry = entries_ptr.add(j);
                                if !(*entry).name.is_null() {
                                    let _ = std::ffi::CString::from_raw((*entry).name);
                                }
                            }
                            libc::free(entries_ptr as *mut libc::c_void);
                        }
                        set_last_error(CErrorCode::InternalError);
                        return CErrorCode::InternalError as c_int;
                    }
                };

                unsafe {
                    let entry = entries_ptr.add(i);
                    (*entry).name = name_cstring.into_raw();
                    (*entry).size = file_info.size;
                    (*entry).is_dir = if file_info.is_dir { 1 } else { 0 };
                    (*entry).mtime = file_info.mtime.timestamp();
                    (*entry).mode = file_info.mode;
                }
            }

            unsafe {
                *entries = entries_ptr;
                *count = entry_count;
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Free file entries array allocated by vault_list_files
///
/// # Safety
/// - `entries` must be array previously allocated by vault_list_files
/// - `count` must match the count returned by vault_list_files
#[no_mangle]
pub extern "C" fn vault_free_file_entries(entries: *mut CFileEntry, count: usize) {
    if entries.is_null() || count == 0 {
        return;
    }

    unsafe {
        for i in 0..count {
            let entry = entries.add(i);
            if !(*entry).name.is_null() {
                let _ = std::ffi::CString::from_raw((*entry).name);
            }
        }
        libc::free(entries as *mut libc::c_void);
    }
}

/// Read a file from the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `path` must be a valid null-terminated C string
/// - `data` will be set to allocated buffer (must be freed with vault_free_file_data)
/// - `size` will be set to file size
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_read_file(
    handle: CVaultHandle,
    path: *const c_char,
    data: *mut *mut u8,
    size: *mut usize,
) -> c_int {
    if handle.is_null() || path.is_null() || data.is_null() || size.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.read_file(path_str) {
        Ok(file_data) => {
            let data_size = file_data.len();

            if data_size == 0 {
                unsafe {
                    *data = ptr::null_mut();
                    *size = 0;
                }
                set_last_error(CErrorCode::Success);
                return CErrorCode::Success as c_int;
            }

            // Allocate buffer for file data
            let data_ptr = unsafe { libc::malloc(data_size) as *mut u8 };
            if data_ptr.is_null() {
                set_last_error(CErrorCode::InternalError);
                return CErrorCode::InternalError as c_int;
            }

            // Copy data to allocated buffer
            unsafe {
                std::ptr::copy_nonoverlapping(file_data.as_ptr(), data_ptr, data_size);
                *data = data_ptr;
                *size = data_size;
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Free file data allocated by vault_read_file
///
/// # Safety
/// - `data` must be buffer previously allocated by vault_read_file
#[no_mangle]
pub extern "C" fn vault_free_file_data(data: *mut u8) {
    if !data.is_null() {
        unsafe {
            libc::free(data as *mut libc::c_void);
        }
    }
}

/// Write a file to the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `path` must be a valid null-terminated C string
/// - `data` must point to valid data buffer or be null for empty file
/// - `size` must be the size of the data buffer
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_write_file(
    handle: CVaultHandle,
    path: *const c_char,
    data: *const u8,
    size: usize,
) -> c_int {
    if handle.is_null() || path.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    let file_data = if data.is_null() || size == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, size) }.to_vec()
    };

    match vault.write_file(path_str, &file_data) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Delete a file from the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `path` must be a valid null-terminated C string
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_delete_file(handle: CVaultHandle, path: *const c_char) -> c_int {
    if handle.is_null() || path.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.delete_file(path_str) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Create a directory in the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `path` must be a valid null-terminated C string
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_create_directory(handle: CVaultHandle, path: *const c_char) -> c_int {
    if handle.is_null() || path.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.create_directory(path_str) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

// Metadata Sections FFI functions

/// Metadata section types for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CMetadataSectionType {
    HiddenTables = 0,
    SharingKeys = 1,
    RecoveryInfo = 2,
    UserSettings = 3,
    AuditLog = 4,
}

impl From<CMetadataSectionType> for crate::format::MetadataSectionType {
    fn from(c_type: CMetadataSectionType) -> Self {
        match c_type {
            CMetadataSectionType::HiddenTables => crate::format::MetadataSectionType::HiddenTables,
            CMetadataSectionType::SharingKeys => crate::format::MetadataSectionType::SharingKeys,
            CMetadataSectionType::RecoveryInfo => crate::format::MetadataSectionType::RecoveryInfo,
            CMetadataSectionType::UserSettings => crate::format::MetadataSectionType::UserSettings,
            CMetadataSectionType::AuditLog => crate::format::MetadataSectionType::AuditLog,
        }
    }
}

/// Set a metadata section in the vault
///
/// # Safety
/// - handle must be a valid vault handle
/// - data must be valid for data_len bytes
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_set_metadata_section(
    handle: CVaultHandle,
    section_type: CMetadataSectionType,
    data: *const u8,
    data_len: usize,
) -> c_int {
    if handle.is_null() || data.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let rust_section_type = section_type.into();

    match vault.set_metadata_section(rust_section_type, data_slice.to_vec()) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            let error_code = CErrorCode::from(e.code());
            set_last_error(error_code);
            error_code as c_int
        }
    }
}

/// Get a metadata section from the vault
///
/// # Safety
/// - handle must be a valid vault handle
/// - data_out and data_len_out must be valid pointers
/// - Caller must free returned data with vault_free_metadata_data
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_get_metadata_section(
    handle: CVaultHandle,
    section_type: CMetadataSectionType,
    data_out: *mut *mut u8,
    data_len_out: *mut usize,
) -> c_int {
    if handle.is_null() || data_out.is_null() || data_len_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };
    let rust_section_type = section_type.into();

    match vault.get_metadata_section(&rust_section_type) {
        Ok(Some(data)) => {
            // Allocate memory using libc::malloc for consistency with free
            let data_len = data.len();
            let data_ptr = unsafe { libc::malloc(data_len) as *mut u8 };

            if data_ptr.is_null() {
                set_last_error(CErrorCode::InternalError);
                return CErrorCode::InternalError as c_int;
            }

            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data_len);
                *data_out = data_ptr;
                *data_len_out = data_len;
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Ok(None) => {
            // No data found
            unsafe {
                *data_out = ptr::null_mut();
                *data_len_out = 0;
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            let error_code = CErrorCode::from(e.code());
            set_last_error(error_code);
            error_code as c_int
        }
    }
}

/// Remove a metadata section from the vault
///
/// # Safety
/// - handle must be a valid vault handle
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_remove_metadata_section(
    handle: CVaultHandle,
    section_type: CMetadataSectionType,
) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };
    let rust_section_type = section_type.into();

    match vault.remove_metadata_section(&rust_section_type) {
        Ok(_) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            let error_code = CErrorCode::from(e.code());
            set_last_error(error_code);
            error_code as c_int
        }
    }
}

/// Migrate vault to use metadata sections format
///
/// # Safety
/// - handle must be a valid vault handle
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_migrate_to_metadata_sections(handle: CVaultHandle) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };

    match vault.migrate_to_metadata_sections() {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            let error_code = CErrorCode::from(e.code());
            set_last_error(error_code);
            error_code as c_int
        }
    }
}

/// Check if vault supports metadata sections
///
/// # Safety
/// - handle must be a valid vault handle
/// - Returns 1 if supported, 0 if not supported, negative on error
#[no_mangle]
pub extern "C" fn vault_supports_metadata_sections(handle: CVaultHandle) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return -1;
    }

    let vault = unsafe { &*handle };

    if vault.supports_metadata_sections() {
        set_last_error(CErrorCode::Success);
        1
    } else {
        set_last_error(CErrorCode::Success);
        0
    }
}

/// Free metadata section data
///
/// # Safety
/// - data must have been allocated by vault_get_metadata_section
/// - data must not be used after this call
#[no_mangle]
pub extern "C" fn vault_free_metadata_data(data: *mut u8) {
    if !data.is_null() {
        unsafe {
            libc::free(data as *mut libc::c_void);
        }
    }
}

// Vault integrity and repair FFI functions

/// Vault validation result structure for FFI
#[repr(C)]
pub struct CVaultValidationResult {
    pub is_valid: c_int,
    pub header_valid: c_int,
    pub file_table_valid: c_int,
    pub total_files: usize,
    pub valid_files: usize,
    pub recoverable_files: usize,
}

/// Vault repair result structure for FFI
#[repr(C)]
pub struct CVaultRepairResult {
    pub success: c_int,
    pub files_recovered: usize,
    pub files_lost: usize,
    pub chunks_recovered: usize,
    pub chunks_lost: usize,
    pub repair_log: *mut *mut c_char,
    pub repair_log_count: usize,
}

/// Validate the integrity of a vault
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `password` must be a valid null-terminated C string
/// - `result_out` must point to valid CVaultValidationResult memory
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_validate_integrity(
    path: *const c_char,
    password: *const c_char,
    result_out: *mut CVaultValidationResult,
) -> c_int {
    if path.is_null() || password.is_null() || result_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match crate::integrity::VaultIntegrityChecker::validate_vault(path_str, password_str) {
        Ok(result) => {
            unsafe {
                (*result_out).is_valid = if result.is_valid { 1 } else { 0 };
                (*result_out).header_valid = if result.header_valid { 1 } else { 0 };
                (*result_out).file_table_valid = if result.file_table_valid { 1 } else { 0 };
                (*result_out).total_files = result.total_files;
                (*result_out).valid_files = result.valid_files;
                (*result_out).recoverable_files = result.recoverable_files;
            }
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Perform a quick integrity check on a vault
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - Returns 1 if valid, 0 if invalid, negative error code on failure
#[no_mangle]
pub extern "C" fn vault_quick_integrity_check(path: *const c_char) -> c_int {
    if path.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match crate::integrity::VaultIntegrityChecker::quick_integrity_check(path_str) {
        Ok(is_valid) => {
            set_last_error(CErrorCode::Success);
            if is_valid {
                1
            } else {
                0
            }
        }
        Err(e) => {
            set_last_error(e.code().into());
            -(e.code() as c_int)
        }
    }
}

/// Repair a corrupted vault
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `password` must be a valid null-terminated C string
/// - `create_backup` should be 1 to create backup, 0 to skip
/// - `result_out` must point to valid CVaultRepairResult memory
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_repair(
    path: *const c_char,
    password: *const c_char,
    create_backup: c_int,
    result_out: *mut CVaultRepairResult,
) -> c_int {
    if path.is_null() || password.is_null() || result_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match crate::integrity::VaultIntegrityChecker::repair_vault(
        path_str,
        password_str,
        create_backup != 0,
    ) {
        Ok(result) => {
            unsafe {
                (*result_out).success = if result.success { 1 } else { 0 };
                (*result_out).files_recovered = result.files_recovered;
                (*result_out).files_lost = result.files_lost;
                (*result_out).chunks_recovered = result.chunks_recovered;
                (*result_out).chunks_lost = result.chunks_lost;

                // Allocate array for repair log strings
                let log_count = result.repair_log.len();
                if log_count > 0 {
                    let log_array = libc::malloc(log_count * std::mem::size_of::<*mut c_char>())
                        as *mut *mut c_char;
                    if log_array.is_null() {
                        set_last_error(CErrorCode::InternalError);
                        return CErrorCode::InternalError as c_int;
                    }

                    for (i, log_entry) in result.repair_log.iter().enumerate() {
                        let c_string = match std::ffi::CString::new(log_entry.as_str()) {
                            Ok(s) => s,
                            Err(_) => {
                                // Clean up previously allocated strings
                                for j in 0..i {
                                    let _ = std::ffi::CString::from_raw(*log_array.add(j));
                                }
                                libc::free(log_array as *mut libc::c_void);
                                set_last_error(CErrorCode::InternalError);
                                return CErrorCode::InternalError as c_int;
                            }
                        };
                        *log_array.add(i) = c_string.into_raw();
                    }

                    (*result_out).repair_log = log_array;
                    (*result_out).repair_log_count = log_count;
                } else {
                    (*result_out).repair_log = ptr::null_mut();
                    (*result_out).repair_log_count = 0;
                }
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Free a vault repair result structure
///
/// # Safety
/// - `result` must be a CVaultRepairResult previously allocated by vault functions
/// - Structure becomes invalid after this call
#[no_mangle]
pub extern "C" fn vault_free_repair_result(result: *mut CVaultRepairResult) {
    if result.is_null() {
        return;
    }

    unsafe {
        let result_data = &mut *result;

        if !result_data.repair_log.is_null() && result_data.repair_log_count > 0 {
            for i in 0..result_data.repair_log_count {
                let log_entry = *result_data.repair_log.add(i);
                if !log_entry.is_null() {
                    let _ = std::ffi::CString::from_raw(log_entry);
                }
            }
            libc::free(result_data.repair_log as *mut libc::c_void);
        }
    }
}

/// Validate integrity of a vault handle
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `password` must be a valid null-terminated C string
/// - `result_out` must point to valid CVaultValidationResult memory
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_validate_handle_integrity(
    handle: CVaultHandle,
    password: *const c_char,
    result_out: *mut CVaultValidationResult,
) -> c_int {
    if handle.is_null() || password.is_null() || result_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.validate_integrity(password_str) {
        Ok(result) => {
            unsafe {
                (*result_out).is_valid = if result.is_valid { 1 } else { 0 };
                (*result_out).header_valid = if result.header_valid { 1 } else { 0 };
                (*result_out).file_table_valid = if result.file_table_valid { 1 } else { 0 };
                (*result_out).total_files = result.total_files;
                (*result_out).valid_files = result.valid_files;
                (*result_out).recoverable_files = result.recoverable_files;
            }
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Perform quick integrity check on a vault handle
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - Returns 1 if valid, 0 if invalid, negative error code on failure
#[no_mangle]
pub extern "C" fn vault_quick_integrity_check_handle(handle: CVaultHandle) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    match vault.quick_integrity_check() {
        Ok(is_valid) => {
            set_last_error(CErrorCode::Success);
            if is_valid {
                1
            } else {
                0
            }
        }
        Err(e) => {
            set_last_error(e.code().into());
            -(e.code() as c_int)
        }
    }
}

/// Free an envelope structure
///
/// # Safety
/// - `envelope` must be a CEnvelope previously allocated by vault functions
/// - Structure becomes invalid after this call
#[no_mangle]
pub extern "C" fn vault_free_envelope(envelope: *mut CEnvelope) {
    if envelope.is_null() {
        return;
    }

    unsafe {
        let envelope_data = &mut *envelope;

        if !envelope_data.encrypted_key.is_null() {
            libc::free(envelope_data.encrypted_key as *mut libc::c_void);
        }
    }
}

// Plausible Deniability FFI Functions

/// Hidden file table metadata structure for FFI
#[repr(C)]
pub struct CHiddenTableMetadata {
    pub table_id: [u8; 16], // UUID as bytes
    pub offset: u64,
    pub size: u64,
    pub reserved_size: u64,
    pub cipher: *mut c_char,
    pub created_at: i64,
    pub is_decoy: c_int,
}

/// Add a hidden file table to the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `password` must be a valid null-terminated C string
/// - `table_id_out` must point to valid memory for 16 bytes (UUID)
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_add_hidden_table(
    handle: CVaultHandle,
    password: *const c_char,
    cipher: CCipherType,
    is_decoy: c_int,
    table_id_out: *mut u8,
) -> c_int {
    if handle.is_null() || password.is_null() || table_id_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.add_hidden_file_table(password_str, cipher.into(), is_decoy != 0) {
        Ok(table_id) => {
            unsafe {
                std::ptr::copy_nonoverlapping(table_id.as_bytes().as_ptr(), table_id_out, 16);
            }
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Remove a hidden file table from the vault
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `table_id` must point to 16 bytes (UUID)
/// - Returns 1 if removed, 0 if not found, negative on error
#[no_mangle]
pub extern "C" fn vault_remove_hidden_table(handle: CVaultHandle, table_id: *const u8) -> c_int {
    if handle.is_null() || table_id.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };

    let table_id_bytes = unsafe { std::slice::from_raw_parts(table_id, 16) };
    let table_uuid = match uuid::Uuid::from_slice(table_id_bytes) {
        Ok(uuid) => uuid,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.remove_hidden_file_table(&table_uuid) {
        Ok(removed) => {
            set_last_error(CErrorCode::Success);
            if removed {
                1
            } else {
                0
            }
        }
        Err(e) => {
            set_last_error(e.code().into());
            -(e.code() as c_int)
        }
    }
}

/// Get the number of hidden file tables
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - Returns table count on success, negative error code on failure
#[no_mangle]
pub extern "C" fn vault_hidden_table_count(handle: CVaultHandle) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    match vault.hidden_file_table_count() {
        Ok(count) => {
            set_last_error(CErrorCode::Success);
            count as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            -(e.code() as c_int)
        }
    }
}

/// List all hidden file table IDs
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `table_ids_out` will be set to allocated array (must be freed with vault_free_table_ids)
/// - `count_out` will be set to the number of table IDs
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_list_hidden_tables(
    handle: CVaultHandle,
    table_ids_out: *mut *mut u8,
    count_out: *mut usize,
) -> c_int {
    if handle.is_null() || table_ids_out.is_null() || count_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &*handle };

    match vault.list_hidden_file_table_ids() {
        Ok(table_ids) => {
            let count = table_ids.len();

            // Allocate array for table IDs (16 bytes each)
            let array_size = count * 16;
            let array_ptr = unsafe { libc::malloc(array_size) as *mut u8 };

            if array_ptr.is_null() {
                set_last_error(CErrorCode::InternalError);
                return CErrorCode::InternalError as c_int;
            }

            // Copy table IDs
            for (i, table_id) in table_ids.iter().enumerate() {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        table_id.as_bytes().as_ptr(),
                        array_ptr.add(i * 16),
                        16,
                    );
                }
            }

            unsafe {
                *table_ids_out = array_ptr;
                *count_out = count;
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Free table IDs array allocated by vault_list_hidden_tables
///
/// # Safety
/// - `table_ids` must be an array previously allocated by vault_list_hidden_tables
#[no_mangle]
pub extern "C" fn vault_free_table_ids(table_ids: *mut u8) {
    if !table_ids.is_null() {
        unsafe {
            libc::free(table_ids as *mut libc::c_void);
        }
    }
}

/// Open a vault with a specific hidden file table password
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `password` must be a valid null-terminated C string
/// - `table_id_out` will be set to the unlocked table ID (16 bytes)
/// - Returns vault handle on success, null on failure
#[no_mangle]
pub extern "C" fn vault_open_hidden_table(
    path: *const c_char,
    password: *const c_char,
    table_id_out: *mut u8,
) -> CVaultHandle {
    if path.is_null() || password.is_null() || table_id_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return ptr::null_mut();
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return ptr::null_mut();
        }
    };

    match crate::vault::Vault::open_with_hidden_table(path_str, password_str) {
        Ok((vault, table_id)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(table_id.as_bytes().as_ptr(), table_id_out, 16);
            }
            set_last_error(CErrorCode::Success);
            Box::into_raw(Box::new(vault))
        }
        Err(e) => {
            set_last_error(e.code().into());
            ptr::null_mut()
        }
    }
}

/// Set the active hidden file table for operations
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `table_id` must point to 16 bytes (UUID)
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_set_active_hidden_table(
    handle: CVaultHandle,
    table_id: *const u8,
) -> c_int {
    if handle.is_null() || table_id.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };

    let table_id_bytes = unsafe { std::slice::from_raw_parts(table_id, 16) };
    let table_uuid = match uuid::Uuid::from_slice(table_id_bytes) {
        Ok(uuid) => uuid,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.set_active_hidden_file_table(table_uuid) {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Create a decoy file table with fake content
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - `password` must be a valid null-terminated C string
/// - `table_id_out` must point to valid memory for 16 bytes (UUID)
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_create_decoy_table(
    handle: CVaultHandle,
    password: *const c_char,
    cipher: CCipherType,
    table_id_out: *mut u8,
) -> c_int {
    if handle.is_null() || password.is_null() || table_id_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };

    let password_str = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    match vault.create_decoy_file_table(password_str, cipher.into()) {
        Ok(table_id) => {
            unsafe {
                std::ptr::copy_nonoverlapping(table_id.as_bytes().as_ptr(), table_id_out, 16);
            }
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Wipe metadata that could reveal the existence of hidden tables
///
/// # Safety
/// - `handle` must be a valid vault handle
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_wipe_revealing_metadata(handle: CVaultHandle) -> c_int {
    if handle.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let vault = unsafe { &mut *handle };

    match vault.wipe_revealing_metadata() {
        Ok(()) => {
            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

/// Get documentation about plausible deniability limitations
///
/// # Safety
/// - Returns a static string that doesn't need to be freed
#[no_mangle]
pub extern "C" fn vault_get_deniability_limitations() -> *const c_char {
    crate::deniability::DeniabilityManager::get_limitations_doc().as_ptr() as *const c_char
}

/// Get the UUID of a vault without opening it (reading header only)
///
/// # Safety
/// - `path` must be a valid null-terminated C string
/// - `uuid_out` will be set to allocated string (must be freed with vault_free_string)
/// - Returns 0 on success, error code on failure
#[no_mangle]
pub extern "C" fn vault_get_id(path: *const c_char, uuid_out: *mut *mut c_char) -> c_int {
    if path.is_null() || uuid_out.is_null() {
        set_last_error(CErrorCode::InvalidArgument);
        return CErrorCode::InvalidArgument as c_int;
    }

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error(CErrorCode::InvalidArgument);
            return CErrorCode::InvalidArgument as c_int;
        }
    };

    // Read only the header to get the UUID
    match crate::format::VaultFormat::read_vault_header(path_str) {
        Ok((header, _)) => {
            let uuid_str = header.vault_uuid.to_string();
            let c_string = match std::ffi::CString::new(uuid_str) {
                Ok(s) => s,
                Err(_) => {
                    set_last_error(CErrorCode::InternalError);
                    return CErrorCode::InternalError as c_int;
                }
            };

            unsafe {
                *uuid_out = c_string.into_raw();
            }

            set_last_error(CErrorCode::Success);
            CErrorCode::Success as c_int
        }
        Err(e) => {
            set_last_error(e.code().into());
            e.code() as c_int
        }
    }
}

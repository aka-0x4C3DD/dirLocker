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
            if removed { 1 } else { 0 }
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

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
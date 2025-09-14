//! Error types and handling for vault operations

use thiserror::Error;

/// Result type for vault operations
pub type VaultResult<T> = Result<T, VaultError>;

/// Main error type for vault operations
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Invalid password or corrupted vault")]
    InvalidPassword,

    #[error("Vault file appears to be corrupted: {details}")]
    CorruptedVault { details: String },

    #[error("Unsupported cipher algorithm: {algorithm}")]
    UnsupportedCipher { algorithm: String },

    #[error("File not found in vault: {path}")]
    FileNotFound { path: String },

    #[error("Insufficient disk space for operation")]
    InsufficientSpace,

    #[error("Permission denied: {details}")]
    PermissionDenied { details: String },

    #[error("Invalid argument: {details}")]
    InvalidArgument { details: String },

    #[error("Internal error: {details}")]
    InternalError { details: String },

    #[error("Cryptographic operation failed: {details}")]
    CryptoError { details: String },

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("UTF-8 encoding error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
}

/// Error codes for FFI compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultErrorCode {
    InvalidPassword,
    CorruptedVault,
    UnsupportedCipher,
    FileNotFound,
    InsufficientSpace,
    PermissionDenied,
    InvalidArgument,
    InternalError,
}

impl VaultError {
    /// Get the error code for FFI compatibility
    pub fn code(&self) -> VaultErrorCode {
        match self {
            VaultError::InvalidPassword => VaultErrorCode::InvalidPassword,
            VaultError::CorruptedVault { .. } => VaultErrorCode::CorruptedVault,
            VaultError::UnsupportedCipher { .. } => VaultErrorCode::UnsupportedCipher,
            VaultError::FileNotFound { .. } => VaultErrorCode::FileNotFound,
            VaultError::InsufficientSpace => VaultErrorCode::InsufficientSpace,
            VaultError::PermissionDenied { .. } => VaultErrorCode::PermissionDenied,
            VaultError::InvalidArgument { .. } => VaultErrorCode::InvalidArgument,
            VaultError::InternalError { .. } => VaultErrorCode::InternalError,
            VaultError::CryptoError { .. } => VaultErrorCode::InternalError,
            VaultError::IoError(_) => VaultErrorCode::InternalError,
            VaultError::JsonError(_) => VaultErrorCode::InternalError,
            VaultError::Utf8Error(_) => VaultErrorCode::InvalidArgument,
        }
    }

    /// Create a corrupted vault error with details
    pub fn corrupted_vault(details: impl Into<String>) -> Self {
        VaultError::CorruptedVault {
            details: details.into(),
        }
    }

    /// Create an unsupported cipher error
    pub fn unsupported_cipher(algorithm: impl Into<String>) -> Self {
        VaultError::UnsupportedCipher {
            algorithm: algorithm.into(),
        }
    }

    /// Create a file not found error
    pub fn file_not_found(path: impl Into<String>) -> Self {
        VaultError::FileNotFound { path: path.into() }
    }

    /// Create a permission denied error
    pub fn permission_denied(details: impl Into<String>) -> Self {
        VaultError::PermissionDenied {
            details: details.into(),
        }
    }

    /// Create an invalid argument error
    pub fn invalid_argument(details: impl Into<String>) -> Self {
        VaultError::InvalidArgument {
            details: details.into(),
        }
    }

    /// Create an internal error
    pub fn internal_error(details: impl Into<String>) -> Self {
        VaultError::InternalError {
            details: details.into(),
        }
    }

    /// Create a cryptographic error
    pub fn crypto_error(details: impl Into<String>) -> Self {
        VaultError::CryptoError {
            details: details.into(),
        }
    }
}

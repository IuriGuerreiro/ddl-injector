// Error types for injection operations

use thiserror::Error;

/// Errors related to process operations
#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("Failed to create process snapshot")]
    SnapshotFailed(#[source] std::io::Error),

    #[error("Failed to enumerate processes")]
    EnumerationFailed(#[source] std::io::Error),

    #[error("Process not found: {0}")]
    ProcessNotFound(u32),

    #[error("Failed to open process handle")]
    OpenProcessFailed(#[source] std::io::Error),

    #[error("Invalid process handle")]
    InvalidHandle,
}

/// Errors related to DLL injection operations
#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("Process operation failed")]
    ProcessError(#[from] ProcessError),

    #[error("DLL file not found: {0}")]
    DllNotFound(String),

    #[error("DLL path must be absolute")]
    RelativePath,

    #[error("Architecture mismatch: injector is {injector}, target is {target}")]
    ArchitectureMismatch { injector: String, target: String },

    #[error("Failed to allocate memory in target process")]
    MemoryAllocationFailed(#[source] std::io::Error),

    #[error("Failed to write to process memory")]
    MemoryWriteFailed(#[source] std::io::Error),

    #[error("Failed to read from process memory")]
    MemoryReadFailed(#[source] std::io::Error),

    #[error("Failed to create remote thread")]
    CreateThreadFailed(#[source] std::io::Error),

    #[error("LoadLibrary address not found in kernel32.dll")]
    LoadLibraryNotFound,

    #[error("Failed to parse PE file")]
    PeParsingFailed(String),

    #[error("Failed to resolve import: {0}")]
    ImportResolutionFailed(String),

    #[error("Failed to apply relocations")]
    RelocationFailed(String),

    #[error("IO error")]
    Io(#[from] std::io::Error),
}

/// Errors that can occur during privilege operations.
#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[error("Failed to open process token")]
    OpenTokenFailed(#[source] std::io::Error),

    #[error("Failed to lookup privilege value")]
    LookupPrivilegeFailed(#[source] std::io::Error),

    #[error("Failed to adjust token privileges")]
    AdjustPrivilegeFailed(#[source] std::io::Error),

    #[error("Privilege not held: {0}")]
    PrivilegeNotHeld(String),

    #[error("Not running as administrator")]
    NotAdministrator,
}

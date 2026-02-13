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

    #[error("Failed to create thread snapshot")]
    ThreadSnapshotFailed(#[source] std::io::Error),

    #[error("Failed to enumerate threads")]
    ThreadEnumerationFailed(#[source] std::io::Error),

    #[error("No alertable threads found")]
    NoAlertableThreads,

    #[error("Failed to open thread")]
    OpenThreadFailed(#[source] std::io::Error),

    #[error("Failed to suspend thread")]
    ThreadSuspendFailed(#[source] std::io::Error),

    #[error("Failed to get thread context")]
    ThreadContextFailed(#[source] std::io::Error),

    #[error("Failed to set thread context")]
    ThreadSetContextFailed(#[source] std::io::Error),

    #[error("Failed to resume thread")]
    ThreadResumeFailed(#[source] std::io::Error),
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

    #[error("NtCreateThreadEx not found in ntdll.dll")]
    NtCreateThreadExNotFound,

    #[error("Failed to parse PE file")]
    PeParsingFailed(String),

    #[error("Failed to resolve import: {0}")]
    ImportResolutionFailed(String),

    #[error("Failed to apply relocations")]
    RelocationFailed(String),

    #[error("Invalid PE file: {0}")]
    InvalidPeFile(String),

    #[error("Invalid DOS header: expected 'MZ', found {0:04X}")]
    InvalidDosHeader(u16),

    #[error("Invalid PE signature: expected 'PE\\0\\0'")]
    InvalidPeSignature,

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Section '{0}' not found in PE file")]
    SectionNotFound(String),

    #[error("Import module '{0}' not found")]
    ImportModuleNotFound(String),

    #[error("Import function '{0}' not found in '{1}'")]
    ImportFunctionNotFound(String, String),

    #[error("Failed to read PE file: {0}")]
    PeReadError(#[source] std::io::Error),

    #[error("Invalid relocation type: {0}")]
    InvalidRelocationType(u16),

    #[error("DLL entry point returned FALSE")]
    DllMainFailed,

    #[error("Failed to create section")]
    SectionCreationFailed(#[source] std::io::Error),

    #[error("Failed to map section view")]
    SectionMappingFailed(#[source] std::io::Error),

    #[error("NtMapViewOfSection not found in ntdll.dll")]
    NtMapViewOfSectionNotFound,

    #[error("NtCreateSection not found in ntdll.dll")]
    NtCreateSectionNotFound,

    #[error("NtUnmapViewOfSection not found in ntdll.dll")]
    NtUnmapViewOfSectionNotFound,

    #[error("Failed to queue APC")]
    ApcQueueFailed(#[source] std::io::Error),

    #[error("Failed to create process")]
    ProcessCreationFailed(#[source] std::io::Error),

    #[error("Failed to generate shellcode")]
    ShellcodeGenerationFailed(String),

    #[error("Reflective loader failed: {0}")]
    ReflectiveLoaderFailed(String),

    #[error("Invalid position-independent code: {0}")]
    PositionIndependentCodeInvalid(String),

    #[error("No suitable threads found for injection")]
    NoSuitableThreads,

    #[error("Export table not found: {0}")]
    ExportTableNotFound(String),

    #[error("Proxy compilation failed: {0}")]
    ProxyCompilationFailed(String),

    #[error("Failed to embed payload: {0}")]
    PayloadEmbeddingFailed(String),

    #[error("Target directory not found: {0}")]
    TargetDirectoryNotFound(String),

    #[error("Operation not supported")]
    UnsupportedOperation,

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

    #[error("Failed to create well-known SID")]
    SidCreationFailed(#[source] std::io::Error),

    #[error("Failed to check token membership")]
    MembershipCheckFailed(#[source] std::io::Error),

    #[error("Privilege not held: {0}")]
    PrivilegeNotHeld(String),

    #[error("Not running as administrator")]
    NotAdministrator,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_error_display() {
        let error = ProcessError::ProcessNotFound(1234);
        assert_eq!(error.to_string(), "Process not found: 1234");

        let error = ProcessError::NoAlertableThreads;
        assert_eq!(error.to_string(), "No alertable threads found");

        let error = ProcessError::InvalidHandle;
        assert_eq!(error.to_string(), "Invalid process handle");
    }

    #[test]
    fn test_injection_error_display() {
        let error = InjectionError::DllNotFound("test.dll".to_string());
        assert_eq!(error.to_string(), "DLL file not found: test.dll");

        let error = InjectionError::RelativePath;
        assert_eq!(error.to_string(), "DLL path must be absolute");

        let error = InjectionError::InvalidPeSignature;
        assert_eq!(
            error.to_string(),
            "Invalid PE signature: expected 'PE\\0\\0'"
        );
    }

    #[test]
    fn test_privilege_error_display() {
        let error = PrivilegeError::NotAdministrator;
        assert_eq!(error.to_string(), "Not running as administrator");

        let error = PrivilegeError::PrivilegeNotHeld("SeDebugPrivilege".to_string());
        assert_eq!(error.to_string(), "Privilege not held: SeDebugPrivilege");
    }

    #[test]
    fn test_architecture_mismatch_error() {
        let error = InjectionError::ArchitectureMismatch {
            injector: "x64".to_string(),
            target: "x86".to_string(),
        };

        let msg = error.to_string();
        assert!(msg.contains("x64"));
        assert!(msg.contains("x86"));
    }

    #[test]
    fn test_import_function_not_found_error() {
        let error = InjectionError::ImportFunctionNotFound(
            "GetProcAddress".to_string(),
            "kernel32.dll".to_string(),
        );

        let msg = error.to_string();
        assert!(msg.contains("GetProcAddress"));
        assert!(msg.contains("kernel32.dll"));
    }

    #[test]
    fn test_invalid_dos_header_error() {
        let error = InjectionError::InvalidDosHeader(0x1234);

        let msg = error.to_string();
        assert!(msg.contains("1234"));
        assert!(msg.contains("MZ"));
    }

    #[test]
    fn test_process_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "test error");
        let error = ProcessError::OpenProcessFailed(io_error);

        assert!(error.to_string().contains("Failed to open process handle"));
    }

    #[test]
    fn test_injection_error_from_process_error() {
        let process_error = ProcessError::ProcessNotFound(5678);
        let injection_error = InjectionError::from(process_error);

        // Should wrap the process error
        let msg = injection_error.to_string();
        assert!(msg.contains("Process operation failed"));
    }

    #[test]
    fn test_injection_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let injection_error = InjectionError::from(io_error);

        assert!(injection_error.to_string().contains("IO error"));
    }

    #[test]
    fn test_relocation_failed_error() {
        let error = InjectionError::RelocationFailed("Invalid relocation entry".to_string());
        let msg = error.to_string();
        assert!(msg.contains("Failed to apply relocations"));
    }

    #[test]
    fn test_invalid_relocation_type() {
        let error = InjectionError::InvalidRelocationType(99);
        let msg = error.to_string();
        assert!(msg.contains("Invalid relocation type"));
        assert!(msg.contains("99"));
    }

    #[test]
    fn test_section_not_found_error() {
        let error = InjectionError::SectionNotFound(".text".to_string());
        let msg = error.to_string();
        assert!(msg.contains("Section"));
        assert!(msg.contains(".text"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_export_table_not_found_error() {
        let error = InjectionError::ExportTableNotFound("No export directory".to_string());
        let msg = error.to_string();
        assert!(msg.contains("Export table not found"));
    }

    #[test]
    fn test_proxy_compilation_failed_error() {
        let error = InjectionError::ProxyCompilationFailed("cargo build failed".to_string());
        let msg = error.to_string();
        assert!(msg.contains("Proxy compilation failed"));
    }

    #[test]
    fn test_payload_embedding_failed_error() {
        let error = InjectionError::PayloadEmbeddingFailed("File copy failed".to_string());
        let msg = error.to_string();
        assert!(msg.contains("Failed to embed payload"));
    }

    #[test]
    fn test_target_directory_not_found_error() {
        let error = InjectionError::TargetDirectoryNotFound("C:\\invalid\\path".to_string());
        let msg = error.to_string();
        assert!(msg.contains("Target directory not found"));
    }

    #[test]
    fn test_unsupported_operation_error() {
        let error = InjectionError::UnsupportedOperation;
        let msg = error.to_string();
        assert_eq!(msg, "Operation not supported");
    }
}

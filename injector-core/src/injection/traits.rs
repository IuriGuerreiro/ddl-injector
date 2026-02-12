//! Core injection traits and types.

use crate::{InjectionError, ProcessHandle};
use std::path::Path;

/// Result type for injection operations.
pub type InjectionResult<T> = Result<T, InjectionError>;

/// Common interface for all DLL injection methods.
///
/// Each injection technique (CreateRemoteThread, Manual Mapping, etc.)
/// implements this trait to provide a unified interface.
pub trait InjectionMethod {
    /// Inject a DLL into the target process.
    ///
    /// # Arguments
    /// * `handle` - Open process handle with required access rights
    /// * `dll_path` - Absolute path to the DLL file
    ///
    /// # Errors
    /// Returns `InjectionError` if injection fails for any reason.
    ///
    /// # Safety
    /// This function performs unsafe operations on the target process.
    /// The DLL must be compatible with the target process architecture.
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()>;

    /// Get the name of this injection method.
    fn name(&self) -> &'static str;

    /// Get the required process access rights for this method.
    fn required_access(&self) -> windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;
}

/// Validate a DLL path before injection.
///
/// Checks:
/// - Path is absolute
/// - File exists
/// - File has .dll extension
pub fn validate_dll_path(path: &Path) -> InjectionResult<()> {
    // Must be absolute path
    if !path.is_absolute() {
        return Err(InjectionError::RelativePath);
    }

    // File must exist
    if !path.exists() {
        return Err(InjectionError::DllNotFound(
            path.display().to_string()
        ));
    }

    // Should have .dll extension
    if path.extension().and_then(|s| s.to_str()) != Some("dll") {
        log::warn!("DLL path does not have .dll extension: {}", path.display());
    }

    Ok(())
}

/// Check if process is 32-bit or 64-bit.
///
/// Returns true if process is 64-bit, false if 32-bit.
pub fn is_process_64bit(handle: &ProcessHandle) -> InjectionResult<bool> {
    use windows::Win32::System::Threading::IsWow64Process;
    use windows::Win32::Foundation::BOOL;

    let mut is_wow64 = BOOL::from(false);

    unsafe {
        IsWow64Process(handle.as_handle(), &mut is_wow64)
            .map_err(|_| InjectionError::Io(std::io::Error::last_os_error()))?;
    }

    // If running on 64-bit Windows:
    // - WoW64 process = 32-bit
    // - Non-WoW64 process = 64-bit
    if cfg!(target_pointer_width = "64") {
        Ok(!is_wow64.as_bool())
    } else {
        // If running on 32-bit Windows, all processes are 32-bit
        Ok(false)
    }
}

/// Validate architecture compatibility between injector and target.
pub fn validate_architecture(handle: &ProcessHandle) -> InjectionResult<()> {
    let target_is_64bit = is_process_64bit(handle)?;
    let injector_is_64bit = cfg!(target_pointer_width = "64");

    if target_is_64bit != injector_is_64bit {
        return Err(InjectionError::ArchitectureMismatch {
            injector: if injector_is_64bit { "64-bit".into() } else { "32-bit".into() },
            target: if target_is_64bit { "64-bit".into() } else { "32-bit".into() },
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dll_path() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("target")
            .join("release")
            .join("test_dll.dll")
    }

    #[test]
    fn test_validate_dll_path_absolute() {
        let dll_path = test_dll_path();
        if !dll_path.exists() {
            // Create a temporary DLL file for testing
            std::fs::create_dir_all(dll_path.parent().unwrap()).ok();
            std::fs::write(&dll_path, b"test").ok();
        }

        let result = validate_dll_path(&dll_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_dll_path_relative() {
        let relative_path = Path::new("test.dll");
        let result = validate_dll_path(relative_path);

        assert!(result.is_err());
        match result {
            Err(InjectionError::RelativePath) => {}
            _ => panic!("Expected RelativePath error"),
        }
    }

    #[test]
    fn test_validate_dll_path_not_exists() {
        let non_existent = PathBuf::from("C:\\nonexistent\\path\\test.dll");
        let result = validate_dll_path(&non_existent);

        assert!(result.is_err());
        match result {
            Err(InjectionError::DllNotFound(_)) => {}
            _ => panic!("Expected DllNotFound error"),
        }
    }

    #[test]
    fn test_validate_dll_path_wrong_extension() {
        // Path without .dll extension should succeed but log warning
        let mut temp_path = std::env::temp_dir();
        temp_path.push("test.txt");

        std::fs::write(&temp_path, b"test").ok();

        let result = validate_dll_path(&temp_path);
        // Should succeed despite wrong extension (just warning)
        assert!(result.is_ok());

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_is_process_64bit_own_process() {
        use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

        let pid = std::process::id();
        let handle = crate::ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION)
            .expect("Failed to open own process");

        let result = is_process_64bit(&handle);
        assert!(result.is_ok());

        let is_64bit = result.unwrap();

        // Should match our own architecture
        #[cfg(target_pointer_width = "64")]
        assert!(is_64bit);

        #[cfg(target_pointer_width = "32")]
        assert!(!is_64bit);
    }

    #[test]
    fn test_validate_architecture_own_process() {
        use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

        let pid = std::process::id();
        let handle = crate::ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION)
            .expect("Failed to open own process");

        // Validating architecture against own process should always succeed
        let result = validate_architecture(&handle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_injection_result_type() {
        // Test that InjectionResult is the correct type alias
        fn returns_injection_result() -> InjectionResult<()> {
            Ok(())
        }

        let result = returns_injection_result();
        assert!(result.is_ok());
    }
}

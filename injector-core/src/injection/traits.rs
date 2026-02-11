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
    #[cfg(target_pointer_width = "64")]
    {
        Ok(!is_wow64.as_bool())
    }

    // If running on 32-bit Windows, all processes are 32-bit
    #[cfg(target_pointer_width = "32")]
    {
        let _ = is_wow64; // Suppress unused variable warning
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

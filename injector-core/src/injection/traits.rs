// Injection method trait definitions

use crate::error::InjectionError;
use crate::process::ProcessHandle;
use std::path::Path;

/// Trait for DLL injection methods
pub trait InjectionMethod {
    /// Inject a DLL into the target process
    fn inject(&self, process: &ProcessHandle, dll_path: &Path) -> Result<(), InjectionError>;
}

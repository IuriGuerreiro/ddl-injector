//! Reflective Loader injection method.
//!
//! This is an advanced stealth technique that loads a DLL without using LoadLibrary:
//! 1. Generate position-independent shellcode (reflective loader)
//! 2. Shellcode parses PEB to find kernel32.dll
//! 3. Resolves required APIs (VirtualAlloc, GetProcAddress, etc.)
//! 4. Allocates memory for DLL image
//! 5. Copies sections from DLL
//! 6. Processes relocations
//! 7. Resolves imports
//! 8. Calls DllMain
//!
//! Advantages:
//! - Does NOT use LoadLibrary (highly stealthy)
//! - DLL does not appear in PEB module list
//! - No standard Windows loader calls
//! - Can bypass many detection mechanisms
//!
//! Disadvantages:
//! - Very complex implementation
//! - PEB structure varies across Windows versions
//! - Difficult to debug
//! - May fail on newer Windows versions
//! - Requires extensive testing
//!
//! Maturity: RESEARCH
//!
//! Note: This is a simplified implementation. A production-ready reflective loader
//! would require:
//! - More robust PEB parsing
//! - Exception handler registration
//! - TLS callback support
//! - Full import resolution
//! - Proper cleanup on failure

use crate::injection::{
    validate_architecture, validate_dll_path, InjectionMethod, InjectionResult,
};
use crate::memory::{write_memory, RemoteMemory};
use crate::pe::PeFile;
use crate::shellcode::{peb_walker, reflective_stub};
use crate::{InjectionError, ProcessHandle};
use std::path::Path;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::*;

/// Reflective Loader injection method.
///
/// WARNING: This is a research-grade implementation and may not work on all systems.
#[derive(Debug, Default)]
pub struct ReflectiveLoaderInjector;

impl ReflectiveLoaderInjector {
    /// Create a new Reflective Loader injector.
    pub fn new() -> Self {
        Self
    }

    /// Build a complete reflective loader payload.
    ///
    /// This combines:
    /// 1. PEB parser shellcode (resolves Windows APIs)
    /// 2. API address table (filled at runtime)
    /// 3. Loader stub shellcode (performs PE loading)
    /// 4. Embedded DLL data
    ///
    /// The result is a single position-independent payload that can be injected
    /// and executed in the target process.
    fn build_reflective_payload(pe: &PeFile) -> InjectionResult<Vec<u8>> {
        log::info!("Building reflective loader payload");

        let mut payload = Vec::new();

        // ========================================================================
        // PART 1: PEB parser shellcode
        // ========================================================================

        // The PEB parser will write to the API table that comes right after it
        let peb_shellcode = peb_walker::generate_peb_parse_x64(
            peb_walker::API_TABLE_SIZE, // API table comes right after PEB walker
        );

        log::debug!("PEB parser shellcode: {} bytes", peb_shellcode.len());
        payload.extend_from_slice(&peb_shellcode);

        // ========================================================================
        // PART 2: API address table (zeroed, filled at runtime by PEB parser)
        // ========================================================================

        let api_table_offset = payload.len();
        log::debug!("API table offset: 0x{:X}", api_table_offset);

        // Reserve space for 4 x64 pointers (VirtualAlloc, VirtualProtect, GetProcAddress, LoadLibraryA)
        payload.extend_from_slice(&vec![0u8; peb_walker::API_TABLE_SIZE]);

        // ========================================================================
        // PART 3: Loader stub shellcode
        // ========================================================================

        // Calculate where DLL data will be (after loader stub)
        // We'll estimate ~4KB for loader stub, then patch later
        let stub_start_offset = payload.len();
        let estimated_stub_size = 4096; // Conservative estimate
        let dll_data_offset = payload.len() + estimated_stub_size;

        log::debug!("Estimated DLL data offset: 0x{:X}", dll_data_offset);

        let loader_stub =
            reflective_stub::generate_loader_stub_x64(pe, api_table_offset, dll_data_offset)?;

        log::debug!("Loader stub shellcode: {} bytes", loader_stub.len());
        payload.extend_from_slice(&loader_stub);

        // ========================================================================
        // PART 4: Embedded DLL data
        // ========================================================================

        let actual_dll_data_offset = payload.len();
        log::debug!("Actual DLL data offset: 0x{:X}", actual_dll_data_offset);

        // If our estimate was wrong, we need to regenerate the stub
        if actual_dll_data_offset != dll_data_offset {
            log::debug!(
                "DLL offset mismatch (estimated: 0x{:X}, actual: 0x{:X}), regenerating stub",
                dll_data_offset,
                actual_dll_data_offset
            );

            // Remove the old stub
            payload.truncate(stub_start_offset);

            // Regenerate with correct offset
            let loader_stub = reflective_stub::generate_loader_stub_x64(
                pe,
                api_table_offset,
                actual_dll_data_offset,
            )?;

            payload.extend_from_slice(&loader_stub);

            // Verify offset is now correct
            let final_dll_offset = payload.len();
            assert_eq!(
                final_dll_offset, actual_dll_data_offset,
                "DLL offset still mismatched after regeneration"
            );
        }

        // Append the raw DLL data
        payload.extend_from_slice(&pe.data);

        log::info!(
            "Reflective payload complete: {} bytes total (PEB: {}, API table: {}, Stub: {}, DLL: {})",
            payload.len(),
            peb_shellcode.len(),
            peb_walker::API_TABLE_SIZE,
            loader_stub.len(),
            pe.data.len()
        );

        Ok(payload)
    }
}

impl InjectionMethod for ReflectiveLoaderInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        log::info!("Starting Reflective Loader injection");
        log::info!("Target DLL: {}", dll_path.display());

        // Step 1: Validate DLL path
        validate_dll_path(dll_path)?;

        // Step 2: Validate architecture compatibility
        validate_architecture(handle)?;

        // Step 3: Parse PE file
        let pe = PeFile::from_file(dll_path)?;
        log::info!(
            "Parsed PE file: {} bytes ({}-bit)",
            pe.data.len(),
            if pe.is_64bit { "64" } else { "32" }
        );

        // Validate architecture (x64 only for now)
        if !pe.is_64bit {
            return Err(InjectionError::ReflectiveLoaderFailed(
                "x86 DLLs not yet supported (x64 only)".to_string(),
            ));
        }

        // Step 4: Build reflective loader payload
        let payload = Self::build_reflective_payload(&pe)?;
        log::info!("Reflective payload size: {} bytes", payload.len());

        // Step 5: Allocate RWX memory in target process
        log::info!("Allocating executable memory in target process");
        let remote_mem = RemoteMemory::allocate_executable(handle.as_handle(), payload.len())?;

        log::info!(
            "Allocated {} bytes at: 0x{:p}",
            payload.len(),
            remote_mem.address()
        );

        // Step 6: Write payload to target process
        log::info!("Writing reflective payload to target process");
        write_memory(handle.as_handle(), remote_mem.address(), &payload)?;

        log::debug!("Payload written successfully");

        // Step 7: Execute payload via CreateRemoteThread
        // The payload starts with the PEB parser, which will:
        // 1. Resolve APIs
        // 2. Jump to loader stub
        // 3. Load the DLL
        // 4. Call DllMain

        log::info!("Creating remote thread to execute reflective loader");

        let thread = unsafe {
            CreateRemoteThread(
                handle.as_handle(),
                None,
                0,
                Some(std::mem::transmute::<
                    *mut u8,
                    unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                >(remote_mem.address())),
                None,
                0,
                None,
            )
            .map_err(|_| InjectionError::CreateThreadFailed(std::io::Error::last_os_error()))?
        };

        log::debug!("Remote thread created, waiting for completion");

        // Step 8: Wait for completion
        unsafe {
            WaitForSingleObject(thread, INFINITE);
        }

        // Get exit code (DllMain return value)
        let mut exit_code = 0u32;
        unsafe {
            GetExitCodeThread(thread, &mut exit_code).map_err(|_| {
                InjectionError::CreateThreadFailed(std::io::Error::last_os_error())
            })?;
        }

        log::debug!("Thread exit code: {}", exit_code);

        unsafe {
            let _ = CloseHandle(thread);
        }

        if exit_code == 0 {
            log::warn!("DllMain returned FALSE (exit code 0)");
            return Err(InjectionError::DllMainFailed);
        }

        log::info!("Reflective Loader injection completed successfully");
        log::info!(
            "Note: DLL will NOT appear in PEB module list (stealth injection)"
        );

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Reflective Loader"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_QUERY_INFORMATION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injector_name() {
        let injector = ReflectiveLoaderInjector::new();
        assert_eq!(injector.name(), "Reflective Loader");
    }

    #[test]
    fn test_required_access() {
        let injector = ReflectiveLoaderInjector::new();
        let access = injector.required_access();

        // Should include all necessary flags
        assert!(access.contains(PROCESS_CREATE_THREAD));
        assert!(access.contains(PROCESS_VM_OPERATION));
        assert!(access.contains(PROCESS_VM_WRITE));
    }

    #[test]
    fn test_build_reflective_payload() {
        // Try to load a test DLL
        let test_dll_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target")
            .join("release")
            .join("test_dll.dll");

        if !test_dll_path.exists() {
            // Skip if test DLL not built
            return;
        }

        let pe = PeFile::from_file(&test_dll_path).expect("Failed to parse test DLL");
        let payload = ReflectiveLoaderInjector::build_reflective_payload(&pe);

        assert!(payload.is_ok(), "Failed to build reflective payload");

        let payload = payload.unwrap();
        assert!(payload.len() > 0);

        // Payload should be larger than the DLL (includes shellcode + DLL)
        assert!(payload.len() > pe.data.len());

        log::info!("Built reflective payload: {} bytes", payload.len());
    }

    #[test]
    fn test_reject_x86_dll() {
        // Create a minimal x86 PE
        let mut pe_data = vec![0u8; 1024];

        // DOS header
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C] = 0x80; // e_lfanew

        // NT signature
        pe_data[0x80] = b'P';
        pe_data[0x81] = b'E';
        pe_data[0x82] = 0;
        pe_data[0x83] = 0;

        // COFF header - x86
        pe_data[0x84] = 0x4C;
        pe_data[0x85] = 0x01; // IMAGE_FILE_MACHINE_I386

        if let Ok(pe) = PeFile::from_bytes(pe_data) {
            let result = ReflectiveLoaderInjector::build_reflective_payload(&pe);
            assert!(
                result.is_err(),
                "Should reject x86 DLLs (x64 only supported)"
            );
        }
    }
}

//! CreateRemoteThread injection method.
//!
//! This is the classic DLL injection technique:
//! 1. Allocate memory in target process
//! 2. Write DLL path to allocated memory
//! 3. Get address of LoadLibraryW in kernel32.dll
//! 4. Create remote thread starting at LoadLibraryW with DLL path as parameter
//!
//! Advantages:
//! - Simple and reliable
//! - Well-documented
//! - Works on all Windows versions
//!
//! Disadvantages:
//! - Easily detected by anti-cheat
//! - DLL appears in module list
//! - Calls DllMain which may trigger detection

use std::path::Path;
use windows::Win32::System::Threading::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::PAGE_READWRITE;
use crate::injection::{InjectionMethod, InjectionResult, validate_dll_path, validate_architecture};
use crate::memory::{RemoteMemory, write_wide_string};
use crate::{ProcessHandle, InjectionError};

/// CreateRemoteThread injection method.
#[derive(Debug, Default)]
pub struct CreateRemoteThreadInjector;

impl CreateRemoteThreadInjector {
    /// Create a new CreateRemoteThread injector.
    pub fn new() -> Self {
        Self
    }

    /// Get the address of LoadLibraryW in kernel32.dll.
    fn get_loadlibrary_address() -> InjectionResult<*mut std::ffi::c_void> {
        use windows::core::s;

        unsafe {
            // Get kernel32.dll module handle
            let kernel32 = GetModuleHandleA(s!("kernel32.dll"))
                .map_err(|_| InjectionError::LoadLibraryNotFound)?;

            // Get LoadLibraryW address
            let loadlib_addr = GetProcAddress(kernel32, s!("LoadLibraryW"))
                .ok_or(InjectionError::LoadLibraryNotFound)?;

            Ok(loadlib_addr as *mut std::ffi::c_void)
        }
    }
}

impl InjectionMethod for CreateRemoteThreadInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        log::info!("Starting CreateRemoteThread injection");
        log::debug!("Target DLL: {}", dll_path.display());

        // Step 1: Validate DLL path
        validate_dll_path(dll_path)?;

        // Step 2: Validate architecture compatibility
        validate_architecture(handle)?;

        // Step 3: Get LoadLibraryW address
        let loadlib_addr = Self::get_loadlibrary_address()?;
        log::debug!("LoadLibraryW address: {:?}", loadlib_addr);

        // Step 4: Allocate memory in target process
        let dll_path_str = dll_path.to_string_lossy();
        let required_size = (dll_path_str.len() + 1) * 2; // UTF-16 + null terminator

        let remote_mem = RemoteMemory::allocate(
            handle.as_handle(),
            required_size,
            PAGE_READWRITE,
        )?;

        log::debug!(
            "Allocated {} bytes at {:?}",
            remote_mem.size(),
            remote_mem.address()
        );

        // Step 5: Write DLL path to remote memory
        write_wide_string(
            handle.as_handle(),
            remote_mem.address(),
            &dll_path_str,
        )?;

        log::debug!("Wrote DLL path to remote memory");

        // Step 6: Create remote thread
        let thread_handle = unsafe {
            CreateRemoteThread(
                handle.as_handle(),
                None,
                0,
                Some(std::mem::transmute::<*mut std::ffi::c_void, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(loadlib_addr)),
                Some(remote_mem.as_ptr()),
                0,
                None,
            )
            .map_err(|_| InjectionError::CreateThreadFailed(
                std::io::Error::last_os_error()
            ))?
        };

        log::info!("Remote thread created: {:?}", thread_handle);

        // Step 7: Wait for thread to complete
        unsafe {
            let wait_result = WaitForSingleObject(thread_handle, 5000); // 5 second timeout

            match wait_result.0 {
                0 => { // WAIT_OBJECT_0
                    log::debug!("Thread completed successfully");

                    // Get thread exit code (DLL module handle)
                    let mut exit_code = 0;
                    if GetExitCodeThread(thread_handle, &mut exit_code).is_ok() {
                        if exit_code == 0 {
                            log::error!("LoadLibraryW returned NULL - DLL failed to load");
                            return Err(InjectionError::Io(std::io::Error::other(
                                "LoadLibraryW failed in target process"
                            )));
                        }
                        log::info!("DLL loaded at address: 0x{:X}", exit_code);
                    }
                }
                0x102 => { // WAIT_TIMEOUT
                    log::warn!("Thread wait timeout - injection may have failed");
                }
                _ => {
                    log::error!("Thread wait failed");
                }
            }

            // Close thread handle
            let _ = windows::Win32::Foundation::CloseHandle(thread_handle);
        }

        log::info!("CreateRemoteThread injection completed successfully");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CreateRemoteThread"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_QUERY_INFORMATION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_loadlibrary_address() {
        let addr = CreateRemoteThreadInjector::get_loadlibrary_address();
        assert!(addr.is_ok());
        assert!(!addr.unwrap().is_null());
    }

    #[test]
    fn test_injector_name() {
        let injector = CreateRemoteThreadInjector::new();
        assert_eq!(injector.name(), "CreateRemoteThread");
    }
}

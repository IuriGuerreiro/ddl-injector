//! Section Mapping injection method.
//!
//! This technique uses NT API section objects to share memory between processes:
//! 1. Parse DLL to get image size
//! 2. Create section with NtCreateSection (shared memory object)
//! 3. Map section into current process
//! 4. Copy DLL data to section
//! 5. Unmap from current process
//! 6. Map same section into target process
//! 7. Create remote thread to execute DLL
//!
//! Advantages:
//! - Memory-efficient (uses shared sections)
//! - Reduces WriteProcessMemory usage
//! - Uses official Windows section APIs
//! - More stealthy than direct memory writes
//!
//! Disadvantages:
//! - Still creates remote thread (detectable)
//! - DLL appears in module list (calls LoadLibrary)
//! - Requires proper relocation handling
//!
//! Maturity: STABLE

use crate::injection::{
    validate_architecture, validate_dll_path, InjectionMethod, InjectionResult,
};
use crate::memory::{write_wide_string, RemoteMemory};
use crate::native::{
    get_nt_create_section, get_nt_map_view_of_section, get_nt_unmap_view_of_section, nt_success,
    SectionInherit, SECTION_ALL_ACCESS, SEC_COMMIT,
};
use crate::pe::PeFile;
use crate::{InjectionError, ProcessHandle};
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Threading::*;

/// Section Mapping injection method.
#[derive(Debug, Default)]
pub struct SectionMappingInjector;

impl SectionMappingInjector {
    /// Create a new Section Mapping injector.
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

impl InjectionMethod for SectionMappingInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        log::info!("Starting Section Mapping injection");
        log::debug!("Target DLL: {}", dll_path.display());

        // Step 1: Validate DLL path
        validate_dll_path(dll_path)?;

        // Step 2: Validate architecture compatibility
        validate_architecture(handle)?;

        // Step 3: Parse PE file to get image size
        let pe = PeFile::from_file(dll_path)?;
        let image_size = pe.size_of_image() as usize;

        log::debug!("DLL image size: {} bytes", image_size);

        // Get NT API functions
        let nt_create_section = get_nt_create_section()?;
        let nt_map_view = get_nt_map_view_of_section()?;
        let nt_unmap_view = get_nt_unmap_view_of_section()?;

        // Step 4: Create section object
        let mut section_handle = HANDLE::default();
        let mut maximum_size = image_size as i64;

        let status = unsafe {
            nt_create_section(
                &mut section_handle,
                SECTION_ALL_ACCESS,
                std::ptr::null(),
                &mut maximum_size,
                PAGE_READWRITE.0,
                SEC_COMMIT,
                HANDLE::default(),
            )
        };

        if !nt_success(status) {
            return Err(InjectionError::SectionCreationFailed(
                std::io::Error::from_raw_os_error(status),
            ));
        }

        log::debug!("Created section: {:?}", section_handle);

        // Ensure section is cleaned up on error
        let _section_guard = SectionGuard(section_handle);

        // Step 5: Map section into current process
        let mut local_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size = image_size;

        let status = unsafe {
            nt_map_view(
                section_handle,
                GetCurrentProcess(),
                &mut local_base,
                0,
                0,
                std::ptr::null(),
                &mut view_size,
                SectionInherit::ViewShare,
                0,
                PAGE_READWRITE.0,
            )
        };

        if !nt_success(status) {
            return Err(InjectionError::SectionMappingFailed(
                std::io::Error::from_raw_os_error(status),
            ));
        }

        log::debug!("Mapped section locally at {:?}", local_base);

        // Ensure local mapping is cleaned up
        let local_mapping_guard = MappingGuard {
            address: local_base,
            process: unsafe { GetCurrentProcess() },
            unmap_fn: nt_unmap_view,
        };

        // Step 6: Copy DLL data to section
        unsafe {
            std::ptr::copy_nonoverlapping(pe.data.as_ptr(), local_base as *mut u8, pe.data.len());
        }

        log::debug!("Copied DLL data to section");

        // Step 7: Unmap from current process (done by guard drop)
        drop(local_mapping_guard);

        // Step 8: Map section into target process
        let mut remote_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut remote_view_size = image_size;

        let status = unsafe {
            nt_map_view(
                section_handle,
                handle.as_handle(),
                &mut remote_base,
                0,
                0,
                std::ptr::null(),
                &mut remote_view_size,
                SectionInherit::ViewShare,
                0,
                PAGE_READWRITE.0,
            )
        };

        if !nt_success(status) {
            return Err(InjectionError::SectionMappingFailed(
                std::io::Error::from_raw_os_error(status),
            ));
        }

        log::debug!("Mapped section in target process at {:?}", remote_base);

        // Step 9: Allocate memory for DLL path in target process
        let dll_path_str = dll_path.to_string_lossy();
        let required_size = (dll_path_str.len() + 1) * 2; // UTF-16 + null terminator

        let path_mem = RemoteMemory::allocate(handle.as_handle(), required_size, PAGE_READWRITE)?;

        log::debug!(
            "Allocated {} bytes for DLL path at {:?}",
            path_mem.size(),
            path_mem.address()
        );

        // Step 10: Write DLL path to remote memory
        write_wide_string(handle.as_handle(), path_mem.address(), &dll_path_str)?;

        log::debug!("Wrote DLL path to remote memory");

        // Step 11: Get LoadLibraryW address
        let loadlib_addr = Self::get_loadlibrary_address()?;
        log::debug!("LoadLibraryW address: {:?}", loadlib_addr);

        // Step 12: Create remote thread to call LoadLibraryW
        let thread_handle = unsafe {
            CreateRemoteThread(
                handle.as_handle(),
                None,
                0,
                Some(std::mem::transmute::<
                    *mut std::ffi::c_void,
                    unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                >(loadlib_addr)),
                Some(path_mem.as_ptr()),
                0,
                None,
            )
            .map_err(|_| InjectionError::CreateThreadFailed(std::io::Error::last_os_error()))?
        };

        log::info!("Remote thread created: {:?}", thread_handle);

        // Step 13: Wait for thread to complete
        unsafe {
            let wait_result = WaitForSingleObject(thread_handle, 5000); // 5 second timeout

            match wait_result {
                WAIT_OBJECT_0 => {
                    log::debug!("Thread completed successfully");

                    // Get thread exit code (DLL module handle)
                    let mut exit_code = 0;
                    if GetExitCodeThread(thread_handle, &mut exit_code).is_ok() {
                        if exit_code == 0 {
                            log::error!("LoadLibraryW returned NULL - DLL failed to load");
                            let _ = CloseHandle(thread_handle);
                            return Err(InjectionError::Io(std::io::Error::other(
                                "LoadLibraryW failed in target process",
                            )));
                        }
                        log::info!("DLL loaded at address: 0x{:X}", exit_code);
                    }
                }
                WAIT_TIMEOUT => {
                    log::warn!("Thread wait timeout - injection may have failed");
                }
                _ => {
                    log::error!("Thread wait failed: {:?}", wait_result);
                }
            }

            // Close thread handle
            let _ = CloseHandle(thread_handle);
        }

        log::info!("Section Mapping injection completed successfully");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "Section Mapping"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_QUERY_INFORMATION
    }
}

/// RAII guard for section handle
struct SectionGuard(HANDLE);

impl Drop for SectionGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// RAII guard for mapped view
struct MappingGuard {
    address: *mut std::ffi::c_void,
    process: HANDLE,
    unmap_fn: unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void) -> i32,
}

impl Drop for MappingGuard {
    fn drop(&mut self) {
        if !self.address.is_null() {
            unsafe {
                let _ = (self.unmap_fn)(self.process, self.address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injector_name() {
        let injector = SectionMappingInjector::new();
        assert_eq!(injector.name(), "Section Mapping");
    }

    #[test]
    fn test_get_loadlibrary_address() {
        let addr = SectionMappingInjector::get_loadlibrary_address();
        assert!(addr.is_ok());
        assert!(!addr.unwrap().is_null());
    }

    #[test]
    fn test_required_access() {
        let injector = SectionMappingInjector::new();
        let access = injector.required_access();

        // Should include all necessary flags
        assert!(access.contains(PROCESS_CREATE_THREAD));
        assert!(access.contains(PROCESS_VM_OPERATION));
        assert!(access.contains(PROCESS_VM_WRITE));
    }
}

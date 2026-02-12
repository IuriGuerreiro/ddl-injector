//! NtCreateThreadEx injection method.
//!
//! Uses the undocumented NtCreateThreadEx function from ntdll.dll.
//! Similar to CreateRemoteThread but uses native API and bypasses some hooks.

use std::path::Path;
use windows::Win32::System::Threading::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use crate::injection::{InjectionMethod, InjectionResult, validate_dll_path, validate_architecture};
use crate::memory::{RemoteMemory, write_wide_string};
use crate::{ProcessHandle, InjectionError};

/// NtCreateThreadEx function signature.
type NtCreateThreadExFn = unsafe extern "system" fn(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut std::ffi::c_void,
    process_handle: HANDLE,
    start_routine: *mut std::ffi::c_void,
    argument: *mut std::ffi::c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut std::ffi::c_void,
) -> i32;

/// NtCreateThreadEx injector.
#[derive(Debug, Default)]
pub struct NtCreateThreadExInjector;

impl NtCreateThreadExInjector {
    pub fn new() -> Self {
        Self
    }

    /// Get NtCreateThreadEx function address.
    fn get_nt_create_thread_ex() -> InjectionResult<NtCreateThreadExFn> {
        use windows::core::s;

        unsafe {
            let ntdll = GetModuleHandleA(s!("ntdll.dll"))
                .map_err(|_| InjectionError::NtCreateThreadExNotFound)?;

            let func_addr = GetProcAddress(ntdll, s!("NtCreateThreadEx"))
                .ok_or(InjectionError::NtCreateThreadExNotFound)?;

            Ok(std::mem::transmute::<unsafe extern "system" fn() -> isize, NtCreateThreadExFn>(func_addr))
        }
    }

    /// Get LoadLibraryW address.
    fn get_loadlibrary_address() -> InjectionResult<*mut std::ffi::c_void> {
        use windows::core::s;

        unsafe {
            let kernel32 = GetModuleHandleA(s!("kernel32.dll"))
                .map_err(|_| InjectionError::LoadLibraryNotFound)?;

            let loadlib_addr = GetProcAddress(kernel32, s!("LoadLibraryW"))
                .ok_or(InjectionError::LoadLibraryNotFound)?;

            Ok(loadlib_addr as *mut std::ffi::c_void)
        }
    }
}

impl InjectionMethod for NtCreateThreadExInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        log::info!("Starting NtCreateThreadEx injection");

        validate_dll_path(dll_path)?;
        validate_architecture(handle)?;

        // Get function pointers
        let nt_create_thread_ex = Self::get_nt_create_thread_ex()?;
        let loadlib_addr = Self::get_loadlibrary_address()?;

        log::debug!("NtCreateThreadEx: {:?}", nt_create_thread_ex as *const ());
        log::debug!("LoadLibraryW: {:?}", loadlib_addr);

        // Allocate and write DLL path
        let dll_path_str = dll_path.to_string_lossy();
        let required_size = (dll_path_str.len() + 1) * 2;

        let remote_mem = RemoteMemory::allocate(
            handle.as_handle(),
            required_size,
            PAGE_READWRITE,
        )?;

        write_wide_string(
            handle.as_handle(),
            remote_mem.address(),
            &dll_path_str,
        )?;

        // Create remote thread using NtCreateThreadEx
        let mut thread_handle = HANDLE::default();

        let status = unsafe {
            nt_create_thread_ex(
                &mut thread_handle,
                0x1FFFFF, // THREAD_ALL_ACCESS
                std::ptr::null_mut(),
                handle.as_handle(),
                loadlib_addr,
                remote_mem.address() as *mut std::ffi::c_void,
                0, // CREATE_SUSPENDED = 0 (run immediately)
                0,
                0,
                0,
                std::ptr::null_mut(),
            )
        };

        if status != 0 {
            log::error!("NtCreateThreadEx failed with status: 0x{:08X}", status);
            return Err(InjectionError::CreateThreadFailed(
                std::io::Error::other(format!("NtCreateThreadEx failed with status 0x{:08X}", status))
            ));
        }

        log::info!("Remote thread created: {:?}", thread_handle);

        // Wait for completion
        unsafe {
            let wait_result = WaitForSingleObject(thread_handle, 10000);

            match wait_result {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0;
                    if GetExitCodeThread(thread_handle, &mut exit_code).is_ok() {
                        if exit_code == 0 {
                            log::error!("LoadLibraryW returned NULL");
                            let _ = CloseHandle(thread_handle);
                            return Err(InjectionError::Io(std::io::Error::other(
                                "LoadLibraryW failed in remote thread"
                            )));
                        }
                        log::info!("DLL loaded at: 0x{:X}", exit_code);
                    }
                }
                WAIT_TIMEOUT => {
                    log::warn!("Thread wait timeout");
                }
                _ => {
                    log::error!("Wait failed");
                }
            }

            let _ = CloseHandle(thread_handle);
        }

        log::info!("NtCreateThreadEx injection completed successfully");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "NtCreateThreadEx"
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
    fn test_nt_create_thread_ex_injector_new() {
        let injector = NtCreateThreadExInjector::new();
        assert_eq!(injector.name(), "NtCreateThreadEx");
    }

    #[test]
    fn test_nt_create_thread_ex_injector_default() {
        let injector = NtCreateThreadExInjector::default();
        assert_eq!(injector.name(), "NtCreateThreadEx");
    }

    #[test]
    fn test_nt_create_thread_ex_name() {
        let injector = NtCreateThreadExInjector::new();
        assert_eq!(injector.name(), "NtCreateThreadEx");
    }

    #[test]
    fn test_nt_create_thread_ex_required_access() {
        let injector = NtCreateThreadExInjector::new();
        let access = injector.required_access();

        // Should include all required flags
        assert!(access.contains(PROCESS_CREATE_THREAD));
        assert!(access.contains(PROCESS_VM_OPERATION));
        assert!(access.contains(PROCESS_VM_WRITE));
        assert!(access.contains(PROCESS_QUERY_INFORMATION));
    }

    #[test]
    fn test_get_nt_create_thread_ex() {
        let result = NtCreateThreadExInjector::get_nt_create_thread_ex();
        assert!(result.is_ok());

        // Function pointer should not be null
        let func = result.unwrap();
        assert!(func as usize != 0);
    }

    #[test]
    fn test_get_loadlibrary_address() {
        let result = NtCreateThreadExInjector::get_loadlibrary_address();
        assert!(result.is_ok());

        let addr = result.unwrap();
        assert!(!addr.is_null());
    }
}

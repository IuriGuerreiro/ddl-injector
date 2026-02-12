//! QueueUserAPC injection method.
//!
//! Queues an APC (Asynchronous Procedure Call) to execute LoadLibraryW
//! in the context of all alertable threads in the target process.
//!
//! Advantages:
//! - Doesn't create new threads
//! - Uses existing thread execution
//! - Less suspicious than CreateRemoteThread
//!
//! Disadvantages:
//! - Requires alertable threads
//! - May take time to execute (threads must enter alertable state)
//! - Not guaranteed to execute immediately

use std::path::Path;
use windows::Win32::System::Threading::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::PAGE_READWRITE;
use crate::injection::{InjectionMethod, InjectionResult, validate_dll_path, validate_architecture};
use crate::memory::{RemoteMemory, write_wide_string};
use crate::process::{ThreadEnumerator, ThreadHandle};
use crate::{ProcessHandle, InjectionError, ProcessError};

/// QueueUserAPC injector.
#[derive(Debug, Default)]
pub struct QueueUserApcInjector;

impl QueueUserApcInjector {
    pub fn new() -> Self {
        Self
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

    /// Queue APC to a thread.
    fn queue_apc_to_thread(
        thread_handle: &ThreadHandle,
        loadlib_addr: *mut std::ffi::c_void,
        dll_path_addr: *mut u8,
    ) -> Result<(), ProcessError> {
        unsafe {
            let result = QueueUserAPC(
                Some(std::mem::transmute::<*mut std::ffi::c_void, unsafe extern "system" fn(usize)>(loadlib_addr)),
                thread_handle.as_handle(),
                dll_path_addr as usize,
            );

            if result == 0 {
                return Err(ProcessError::OpenThreadFailed(
                    std::io::Error::last_os_error()
                ));
            }
        }

        Ok(())
    }
}

impl InjectionMethod for QueueUserApcInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        log::info!("Starting QueueUserAPC injection");

        validate_dll_path(dll_path)?;
        validate_architecture(handle)?;

        // Get LoadLibraryW address
        let loadlib_addr = Self::get_loadlibrary_address()?;
        log::debug!("LoadLibraryW address: {:?}", loadlib_addr);

        // Allocate memory for DLL path
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

        log::debug!("DLL path written to: {:?}", remote_mem.address());

        // Enumerate threads
        let process_id = unsafe {
            GetProcessId(handle.as_handle())
        };

        let threads = ThreadEnumerator::enumerate(process_id)?;

        if threads.is_empty() {
            return Err(InjectionError::ProcessError(
                ProcessError::NoAlertableThreads
            ));
        }

        log::info!("Found {} threads, queuing APCs", threads.len());

        let mut queued_count = 0;

        // Queue APC to all threads
        for thread_info in &threads {
            match ThreadHandle::open(
                thread_info.thread_id,
                THREAD_SET_CONTEXT,
            ) {
                Ok(thread_handle) => {
                    if Self::queue_apc_to_thread(
                        &thread_handle,
                        loadlib_addr,
                        remote_mem.address(),
                    ).is_ok() {
                        queued_count += 1;
                        log::debug!("APC queued to thread {}", thread_info.thread_id);
                    }
                }
                Err(e) => {
                    log::debug!("Failed to open thread {}: {}", thread_info.thread_id, e);
                }
            }
        }

        if queued_count == 0 {
            return Err(InjectionError::ProcessError(
                ProcessError::NoAlertableThreads
            ));
        }

        log::info!("Successfully queued APCs to {} threads", queued_count);
        log::warn!("APCs will execute when threads enter alertable state");

        std::mem::forget(remote_mem); // Keep DLL path in memory

        Ok(())
    }

    fn name(&self) -> &'static str {
        "QueueUserAPC"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_user_apc_injector_new() {
        let injector = QueueUserApcInjector::new();
        assert_eq!(injector.name(), "QueueUserAPC");
    }

    #[test]
    fn test_queue_user_apc_injector_default() {
        let injector = QueueUserApcInjector::default();
        assert_eq!(injector.name(), "QueueUserAPC");
    }

    #[test]
    fn test_queue_user_apc_name() {
        let injector = QueueUserApcInjector::new();
        assert_eq!(injector.name(), "QueueUserAPC");
    }

    #[test]
    fn test_queue_user_apc_required_access() {
        let injector = QueueUserApcInjector::new();
        let access = injector.required_access();

        // Should include required flags
        assert!(access.contains(PROCESS_VM_OPERATION));
        assert!(access.contains(PROCESS_VM_WRITE));
        assert!(access.contains(PROCESS_QUERY_INFORMATION));
    }

    #[test]
    fn test_get_loadlibrary_address() {
        let result = QueueUserApcInjector::get_loadlibrary_address();
        assert!(result.is_ok());

        let addr = result.unwrap();
        assert!(!addr.is_null());
    }
}

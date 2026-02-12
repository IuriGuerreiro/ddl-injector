//! Early Bird APC injection method.
//!
//! This technique queues an APC to a suspended process before it starts:
//! 1. Create target process in suspended state
//! 2. Allocate memory in suspended process
//! 3. Write DLL path to memory
//! 4. Queue APC to main thread (LoadLibraryW)
//! 5. Resume main thread - APC executes before main application code
//!
//! Advantages:
//! - Executes before main application code
//! - More reliable than standard APC (no need for alertable threads)
//! - Process initializes with DLL already loaded
//! - Useful for early hooks and initialization
//!
//! Disadvantages:
//! - Requires process creation (cannot attach to existing process)
//! - Still uses LoadLibrary (DLL appears in module list)
//! - Different signature than other methods (needs executable path)
//!
//! Maturity: STABLE

use crate::injection::InjectionResult;
use crate::memory::{write_wide_string, RemoteMemory};
use crate::InjectionError;
use std::path::Path;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Threading::*;

/// Early Bird APC injection method.
///
/// Note: This method requires creating a process rather than attaching to an existing one.
#[derive(Debug, Default)]
pub struct EarlyBirdApcInjector;

impl EarlyBirdApcInjector {
    /// Create a new Early Bird APC injector.
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

    /// Inject DLL into a newly created process.
    ///
    /// # Arguments
    /// * `executable_path` - Path to the executable to launch
    /// * `dll_path` - Path to the DLL to inject
    /// * `command_line` - Optional command line arguments
    ///
    /// # Returns
    /// Process ID of the created process on success
    pub fn inject_and_launch(
        executable_path: &Path,
        dll_path: &Path,
        command_line: Option<&str>,
    ) -> InjectionResult<u32> {
        log::info!("Starting Early Bird APC injection");
        log::debug!("Executable: {}", executable_path.display());
        log::debug!("Target DLL: {}", dll_path.display());

        // Validate paths
        if !executable_path.exists() {
            return Err(InjectionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Executable not found: {}", executable_path.display()),
            )));
        }

        if !dll_path.is_absolute() {
            return Err(InjectionError::RelativePath);
        }

        if !dll_path.exists() {
            return Err(InjectionError::DllNotFound(dll_path.display().to_string()));
        }

        // Prepare command line
        let mut cmd_line_buf: Vec<u16>;
        let cmd_line_ptr = if let Some(args) = command_line {
            let full_cmd = format!("\"{}\" {}", executable_path.display(), args);
            cmd_line_buf = full_cmd.encode_utf16().chain(Some(0)).collect();
            cmd_line_buf.as_mut_ptr()
        } else {
            let exe_str = executable_path.to_string_lossy();
            cmd_line_buf = exe_str.encode_utf16().chain(Some(0)).collect();
            cmd_line_buf.as_mut_ptr()
        };

        // Create process in suspended state
        let mut startup_info = STARTUPINFOW::default();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info = PROCESS_INFORMATION::default();

        log::debug!("Creating process in suspended state");

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                PWSTR(cmd_line_ptr),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                PCWSTR::null(),
                &startup_info,
                &mut process_info,
            )
            .map_err(|_| InjectionError::ProcessCreationFailed(std::io::Error::last_os_error()))?;
        }

        log::info!(
            "Process created: PID {} TID {}",
            process_info.dwProcessId,
            process_info.dwThreadId
        );

        // Ensure handles are cleaned up
        let _process_guard = HandleGuard(process_info.hProcess);
        let _thread_guard = HandleGuard(process_info.hThread);

        // Allocate memory for DLL path in target process
        let dll_path_str = dll_path.to_string_lossy();
        let required_size = (dll_path_str.len() + 1) * 2; // UTF-16 + null terminator

        let remote_mem =
            RemoteMemory::allocate(process_info.hProcess, required_size, PAGE_READWRITE)?;

        log::debug!(
            "Allocated {} bytes at {:?}",
            remote_mem.size(),
            remote_mem.address()
        );

        // Write DLL path to remote memory
        write_wide_string(
            process_info.hProcess,
            remote_mem.address(),
            &dll_path_str,
        )?;

        log::debug!("Wrote DLL path to remote memory");

        // Get LoadLibraryW address
        let loadlib_addr = Self::get_loadlibrary_address()?;
        log::debug!("LoadLibraryW address: {:?}", loadlib_addr);

        // Queue APC to the main thread
        unsafe {
            let result = QueueUserAPC(
                Some(std::mem::transmute::<
                    *mut std::ffi::c_void,
                    unsafe extern "system" fn(usize),
                >(loadlib_addr)),
                process_info.hThread,
                remote_mem.address() as usize,
            );

            if result == 0 {
                return Err(InjectionError::ApcQueueFailed(
                    std::io::Error::last_os_error(),
                ));
            }
        }

        log::info!("APC queued to main thread");

        // Resume the main thread - APC will execute before main code
        unsafe {
            let resume_count = ResumeThread(process_info.hThread);
            log::debug!("Thread resumed (previous suspend count: {})", resume_count);
        }

        log::info!("Early Bird APC injection completed successfully");
        log::info!("Process is now running with PID {}", process_info.dwProcessId);

        Ok(process_info.dwProcessId)
    }

    /// Get the method name.
    pub fn name(&self) -> &'static str {
        "Early Bird APC"
    }
}

/// RAII guard for handle cleanup
struct HandleGuard(windows::Win32::Foundation::HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injector_name() {
        let injector = EarlyBirdApcInjector::new();
        assert_eq!(injector.name(), "Early Bird APC");
    }

    #[test]
    fn test_get_loadlibrary_address() {
        let addr = EarlyBirdApcInjector::get_loadlibrary_address();
        assert!(addr.is_ok());
        assert!(!addr.unwrap().is_null());
    }

    // Note: Full integration test would require actual process creation
    // and is marked as #[ignore] in tests/integration_test.rs
}

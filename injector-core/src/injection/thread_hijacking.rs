//! Thread Hijacking injection method.
//!
//! This technique hijacks an existing thread to execute injection code:
//! 1. Enumerate threads in target process
//! 2. Select a suitable thread (avoid critical threads)
//! 3. Suspend the thread
//! 4. Get thread context (CPU registers)
//! 5. Allocate memory for DLL path + shellcode
//! 6. Generate shellcode that calls LoadLibraryW and restores execution
//! 7. Modify instruction pointer (RIP/EIP) to point to shellcode
//! 8. Set thread context and resume
//!
//! Advantages:
//! - Does not create new remote thread (avoids thread creation hooks)
//! - Uses existing threads (more stealthy)
//! - No direct CreateRemoteThread API call
//!
//! Disadvantages:
//! - Can cause deadlocks if thread holds locks
//! - Requires careful context preservation
//! - Architecture-specific shellcode needed
//! - Risk of process crash if not done correctly
//!
//! Maturity: EXPERIMENTAL

use crate::injection::{
    validate_architecture, validate_dll_path, InjectionMethod, InjectionResult,
};
use crate::memory::{write_memory, write_wide_string, RemoteMemory};
use crate::process::{ThreadContext, ThreadEnumerator, ThreadHandle};
use crate::shellcode::generate_loadlibrary_shellcode;
use crate::{InjectionError, ProcessHandle};
use std::path::Path;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Threading::*;

/// Thread Hijacking injection method.
#[derive(Debug, Default)]
pub struct ThreadHijackingInjector;

impl ThreadHijackingInjector {
    /// Create a new Thread Hijacking injector.
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

    /// Select a suitable thread for hijacking.
    ///
    /// Avoids the first thread (main thread) to reduce crash risk.
    fn select_thread(pid: u32) -> InjectionResult<u32> {
        let threads = ThreadEnumerator::enumerate(pid)?;

        if threads.is_empty() {
            return Err(InjectionError::NoSuitableThreads);
        }

        // Skip the first thread (main thread) if possible
        if threads.len() > 1 {
            log::debug!(
                "Selected thread {} (avoiding main thread)",
                threads[1].thread_id
            );
            Ok(threads[1].thread_id)
        } else {
            log::warn!("Only one thread found - using main thread (higher risk)");
            Ok(threads[0].thread_id)
        }
    }
}

impl InjectionMethod for ThreadHijackingInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        log::info!("Starting Thread Hijacking injection");
        log::debug!("Target DLL: {}", dll_path.display());

        // Step 1: Validate DLL path
        validate_dll_path(dll_path)?;

        // Step 2: Validate architecture compatibility
        validate_architecture(handle)?;

        // Step 3: Select a thread to hijack
        let thread_id = Self::select_thread(handle.pid())?;
        log::debug!("Selected thread ID: {}", thread_id);

        // Step 4: Open thread handle with required access
        let thread = ThreadHandle::open(
            thread_id,
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        )?;

        // Step 5: Suspend the thread
        unsafe {
            let suspend_count = SuspendThread(thread.as_handle());
            if suspend_count == u32::MAX {
                return Err(InjectionError::Io(std::io::Error::last_os_error()));
            }
            log::debug!("Thread suspended (suspend count: {})", suspend_count);
        }

        // Ensure thread is resumed on error
        let _resume_guard = ResumeGuard(thread.as_handle());

        // Step 6: Get thread context
        let mut context = ThreadContext::capture(&thread)?;
        let original_ip = context.get_instruction_pointer();
        log::debug!("Original instruction pointer: 0x{:X}", original_ip);

        // Step 7: Allocate memory for DLL path
        let dll_path_str = dll_path.to_string_lossy();
        let path_size = (dll_path_str.len() + 1) * 2; // UTF-16 + null terminator

        let path_mem =
            RemoteMemory::allocate(handle.as_handle(), path_size, PAGE_EXECUTE_READWRITE)?;

        log::debug!(
            "Allocated {} bytes for DLL path at {:?}",
            path_mem.size(),
            path_mem.address()
        );

        // Write DLL path to remote memory
        write_wide_string(handle.as_handle(), path_mem.address(), &dll_path_str)?;

        // Step 8: Get LoadLibraryW address
        let loadlib_addr = Self::get_loadlibrary_address()?;
        log::debug!("LoadLibraryW address: {:?}", loadlib_addr);

        // Step 9: Generate shellcode
        let shellcode = generate_loadlibrary_shellcode(
            path_mem.address() as usize,
            loadlib_addr as usize,
            original_ip,
        )?;

        log::debug!("Generated {} bytes of shellcode", shellcode.len());

        // Step 10: Allocate memory for shellcode
        let shellcode_mem = RemoteMemory::allocate(
            handle.as_handle(),
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
        )?;

        log::debug!(
            "Allocated {} bytes for shellcode at {:?}",
            shellcode_mem.size(),
            shellcode_mem.address()
        );

        // Step 11: Write shellcode to remote memory
        write_memory(
            handle.as_handle(),
            shellcode_mem.address(),
            &shellcode,
        )?;

        log::debug!("Wrote shellcode to remote memory");

        // Step 12: Modify instruction pointer to point to shellcode
        context.set_instruction_pointer(shellcode_mem.address() as usize);
        log::debug!(
            "Modified instruction pointer to: 0x{:X}",
            shellcode_mem.address() as usize
        );

        // Step 13: Set the modified context
        context.apply(&thread)?;
        log::debug!("Applied modified context to thread");

        // Step 14: Resume thread (done by guard drop)
        drop(_resume_guard);
        unsafe {
            let resume_count = ResumeThread(thread.as_handle());
            log::debug!("Thread resumed (suspend count: {})", resume_count);
        }

        log::info!("Thread Hijacking injection completed successfully");
        log::warn!("Note: Monitor target process for crashes - thread hijacking is experimental");

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Thread Hijacking"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_QUERY_INFORMATION
            | PROCESS_CREATE_THREAD // Needed for thread enumeration
    }
}

/// RAII guard to ensure thread is resumed
struct ResumeGuard(windows::Win32::Foundation::HANDLE);

impl Drop for ResumeGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                ResumeThread(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injector_name() {
        let injector = ThreadHijackingInjector::new();
        assert_eq!(injector.name(), "Thread Hijacking");
    }

    #[test]
    fn test_get_loadlibrary_address() {
        let addr = ThreadHijackingInjector::get_loadlibrary_address();
        assert!(addr.is_ok());
        assert!(!addr.unwrap().is_null());
    }

    #[test]
    fn test_select_thread_own_process() {
        let pid = std::process::id();
        let result = ThreadHijackingInjector::select_thread(pid);

        // Should succeed for own process
        assert!(result.is_ok());
        let thread_id = result.unwrap();
        assert!(thread_id > 0);
    }

    #[test]
    fn test_required_access() {
        let injector = ThreadHijackingInjector::new();
        let access = injector.required_access();

        // Should include all necessary flags
        assert!(access.contains(PROCESS_VM_OPERATION));
        assert!(access.contains(PROCESS_VM_WRITE));
        assert!(access.contains(PROCESS_VM_READ));
    }
}

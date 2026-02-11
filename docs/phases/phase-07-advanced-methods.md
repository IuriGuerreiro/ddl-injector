# Phase 7: Advanced Injection Methods

**Status:** ⏳ Pending
**Estimated Time:** 6-8 hours
**Complexity:** Medium-High

## Phase Overview

Implement two additional injection methods: QueueUserAPC (queues APC to all alertable threads) and NtCreateThreadEx (uses undocumented ntdll function). These methods provide alternatives to CreateRemoteThread with different stealth profiles and use cases.

## Objectives

- [ ] Implement thread enumeration
- [ ] Create QueueUserAPC injector
- [ ] Implement NtCreateThreadEx injector
- [ ] Add dynamic function loading for undocumented APIs
- [ ] Handle alertable thread detection
- [ ] Update UI to show all four methods
- [ ] Test with various target processes

## Prerequisites

- ✅ Phase 6: Manual mapping complete
- Understanding of Windows threading model
- Knowledge of APC (Asynchronous Procedure Call) mechanism
- Familiarity with undocumented APIs

## Learning Resources

- [QueueUserAPC MSDN](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [Thread32First/Next MSDN](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)
- [Undocumented NtCreateThreadEx](https://www.unknowncheats.me/forum/c-and-c-/68869-ntcreatethreadex.html)
- [APC Injection Explained](https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection)

## File Structure

```
injector-core/src/
├── process/
│   └── thread.rs              # Thread enumeration ← NEW
├── injection/
│   ├── queue_user_apc.rs      # APC injection ← NEW
│   └── nt_create_thread.rs    # NtCreateThreadEx ← NEW
└── error.rs                   # Add thread errors ← UPDATE
```

## Dependencies

No new dependencies needed.

## Step-by-Step Implementation

### Step 1: Add Thread Error Types

**File:** `injector-core/src/error.rs` (update ProcessError)

```rust
#[derive(Debug, Error)]
pub enum ProcessError {
    // ... existing variants ...

    #[error("Failed to create thread snapshot")]
    ThreadSnapshotFailed(#[source] io::Error),

    #[error("Failed to enumerate threads")]
    ThreadEnumerationFailed(#[source] io::Error),

    #[error("No alertable threads found")]
    NoAlertableThreads,

    #[error("Failed to open thread")]
    OpenThreadFailed(#[source] io::Error),
}
```

### Step 2: Implement Thread Enumeration

**File:** `injector-core/src/process/thread.rs`

```rust
//! Thread enumeration and management.

use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use crate::ProcessError;

/// Information about a thread.
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub base_priority: i32,
}

/// RAII wrapper for thread handle.
pub struct ThreadHandle {
    handle: HANDLE,
}

impl ThreadHandle {
    /// Open a thread by ID.
    pub fn open(thread_id: u32, access: THREAD_ACCESS_RIGHTS) -> Result<Self, ProcessError> {
        let handle = unsafe {
            OpenThread(access, false, thread_id)
                .map_err(|_| ProcessError::OpenThreadFailed(
                    std::io::Error::last_os_error()
                ))?
        };

        Ok(Self { handle })
    }

    /// Get raw handle.
    pub fn as_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Thread enumerator.
pub struct ThreadEnumerator;

impl ThreadEnumerator {
    /// Enumerate all threads belonging to a process.
    pub fn enumerate(process_id: u32) -> Result<Vec<ThreadInfo>, ProcessError> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|_| ProcessError::ThreadSnapshotFailed(
                    std::io::Error::last_os_error()
                ))?
        };

        let _guard = SnapshotGuard(snapshot);

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        unsafe {
            Thread32First(snapshot, &mut entry)
                .map_err(|_| ProcessError::ThreadEnumerationFailed(
                    std::io::Error::last_os_error()
                ))?;
        }

        let mut threads = Vec::new();

        loop {
            if entry.th32OwnerProcessID == process_id {
                threads.push(ThreadInfo {
                    thread_id: entry.th32ThreadID,
                    owner_process_id: entry.th32OwnerProcessID,
                    base_priority: entry.tpBasePri,
                });
            }

            if unsafe { Thread32Next(snapshot, &mut entry).is_err() } {
                break;
            }
        }

        log::debug!("Found {} threads for PID {}", threads.len(), process_id);
        Ok(threads)
    }
}

struct SnapshotGuard(HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
```

### Step 3: Implement QueueUserAPC Injector

**File:** `injector-core/src/injection/queue_user_apc.rs`

```rust
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
            QueueUserAPC(
                Some(std::mem::transmute(loadlib_addr)),
                thread_handle.as_handle(),
                dll_path_addr as usize,
            )
            .map_err(|_| ProcessError::OpenThreadFailed(
                std::io::Error::last_os_error()
            ))?;
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
```

### Step 4: Implement NtCreateThreadEx Injector

**File:** `injector-core/src/injection/nt_create_thread.rs`

```rust
//! NtCreateThreadEx injection method.
//!
//! Uses the undocumented NtCreateThreadEx function from ntdll.dll.
//! Similar to CreateRemoteThread but uses native API.

use std::path::Path;
use windows::Win32::System::Threading::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
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

            Ok(std::mem::transmute(func_addr))
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
            log::error!("NtCreateThreadEx failed with status: 0x{:X}", status);
            return Err(InjectionError::CreateThreadFailed(
                std::io::Error::last_os_error()
            ));
        }

        log::info!("Remote thread created: {:?}", thread_handle);

        // Wait for completion
        unsafe {
            let wait_result = WaitForSingleObject(thread_handle, 5000);

            match wait_result {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0;
                    if GetExitCodeThread(thread_handle, &mut exit_code).is_ok() {
                        if exit_code == 0 {
                            log::error!("LoadLibraryW returned NULL");
                            let _ = CloseHandle(thread_handle);
                            return Err(InjectionError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "LoadLibraryW failed"
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

        log::info!("NtCreateThreadEx injection completed");
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
```

### Step 5: Update Module Exports

**File:** `injector-core/src/process/mod.rs` (update)

```rust
//! Process enumeration and management.

mod enumerator;
mod handle;
mod info;
mod thread;

pub use enumerator::ProcessEnumerator;
pub use handle::ProcessHandle;
pub use info::ProcessInfo;
pub use thread::{ThreadEnumerator, ThreadHandle, ThreadInfo};
```

**File:** `injector-core/src/injection/mod.rs` (update)

```rust
//! DLL injection methods and utilities.

pub mod traits;
pub mod create_remote_thread;
pub mod manual_map;
pub mod queue_user_apc;
pub mod nt_create_thread;

pub use traits::{
    InjectionMethod,
    InjectionResult,
    validate_dll_path,
    validate_architecture,
    is_process_64bit,
};
pub use create_remote_thread::CreateRemoteThreadInjector;
pub use manual_map::ManualMapInjector;
pub use queue_user_apc::QueueUserApcInjector;
pub use nt_create_thread::NtCreateThreadExInjector;
```

### Step 6: Update UI

**File:** `injector-ui/src/app.rs` (update InjectionMethodType)

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectionMethodType {
    CreateRemoteThread,
    ManualMapping,
    QueueUserApc,
    NtCreateThreadEx,
}

impl InjectionMethodType {
    fn name(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "CreateRemoteThread",
            Self::ManualMapping => "Manual Mapping",
            Self::QueueUserApc => "QueueUserAPC",
            Self::NtCreateThreadEx => "NtCreateThreadEx",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "Classic injection via remote thread",
            Self::ManualMapping => "Stealthy PE mapping without LoadLibrary",
            Self::QueueUserApc => "APC injection to alertable threads",
            Self::NtCreateThreadEx => "Native API thread creation",
        }
    }
}
```

Update `perform_injection()`:

```rust
fn perform_injection(&mut self) {
    // ... validation ...

    let result = match self.injection_method {
        InjectionMethodType::CreateRemoteThread => {
            CreateRemoteThreadInjector::new().inject(&handle, dll_path)
        }
        InjectionMethodType::ManualMapping => {
            ManualMapInjector::new().inject(&handle, dll_path)
        }
        InjectionMethodType::QueueUserApc => {
            QueueUserApcInjector::new().inject(&handle, dll_path)
        }
        InjectionMethodType::NtCreateThreadEx => {
            NtCreateThreadExInjector::new().inject(&handle, dll_path)
        }
    };

    // ... error handling ...
}
```

## Testing Checklist

- [ ] Thread enumeration works
- [ ] QueueUserAPC queues to all threads
- [ ] NtCreateThreadEx creates thread successfully
- [ ] All four methods appear in UI dropdown
- [ ] Each method can inject test DLL
- [ ] Appropriate errors for edge cases

## Common Pitfalls

### 1. APC Not Executing
**Problem:** APCs only execute when threads are alertable
**Solution:** Warn user that execution may be delayed

### 2. NtCreateThreadEx Signature
**Problem:** Undocumented API signature may change
**Solution:** Test on multiple Windows versions

### 3. Thread Access Rights
**Problem:** Wrong access rights for thread operations
**Solution:** Use THREAD_SET_CONTEXT for APC

### 4. Missing Threads
**Problem:** Not all threads accessible
**Solution:** Gracefully handle access denied

## Completion Criteria

- ✅ Thread enumeration implemented
- ✅ QueueUserAPC injector works
- ✅ NtCreateThreadEx injector works
- ✅ UI shows all four methods
- ✅ All methods tested successfully
- ✅ Tests pass

## Git Commit

```bash
git add injector-core/src/process/thread.rs
git add injector-core/src/injection/queue_user_apc.rs
git add injector-core/src/injection/nt_create_thread.rs
git commit -m "feat: implement QueueUserAPC and NtCreateThreadEx injection

- Add thread enumeration with snapshot API
- Implement QueueUserAPC injection to alertable threads
- Add NtCreateThreadEx using undocumented ntdll function
- Update UI to show all four injection methods
- Include comprehensive error handling

All injection methods complete.

Follows docs/phases/phase-07-advanced-methods.md
"
```

## Next Steps

Proceed to **Phase 8: Configuration** (docs/phases/phase-08-config.md)

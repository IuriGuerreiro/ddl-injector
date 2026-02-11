# Phase 3: Basic Injection (CreateRemoteThread)

**Status:** ⏳ Pending
**Estimated Time:** 6-8 hours
**Complexity:** Medium-High

## Phase Overview

Implement the foundational CreateRemoteThread injection method. This classic technique allocates memory in the target process, writes the DLL path, and creates a remote thread that calls LoadLibraryW. This phase also establishes the InjectionMethod trait that all injection techniques will implement, providing a unified interface.

**CRITICAL:** Strict architecture validation (32-bit vs 64-bit) MUST be performed before any remote memory is allocated or written to prevent target process crashes.

## Objectives

- [ ] Define InjectionMethod trait with inject() method
- [ ] Implement memory allocation and writing in target process
- [ ] Create CreateRemoteThread injection method
- [ ] Add DLL path validation (absolute path, exists, architecture check)
- [ ] Implement comprehensive error handling
- [ ] Add architecture mismatch detection (32-bit vs 64-bit)
- [ ] Write unit and integration tests

## Prerequisites

- ✅ Phase 2: Process enumeration complete
- Understanding of Windows memory management
- Familiarity with LoadLibraryW and DLL loading
- Knowledge of process memory layout

## Learning Resources

- [VirtualAllocEx MSDN](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory MSDN](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [CreateRemoteThread MSDN](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [LoadLibraryW MSDN](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw)

## File Structure

```
injector-core/src/
├── injection/
│   ├── mod.rs                      # Export public types
│   ├── traits.rs                   # InjectionMethod trait ← NEW
│   └── create_remote_thread.rs     # CRT implementation ← NEW
├── memory/
│   ├── mod.rs                      # Export memory types
│   ├── allocator.rs                # RemoteMemory RAII ← NEW
│   └── writer.rs                   # Memory writing ← NEW
├── error.rs                        # Update with new errors
└── lib.rs                          # Re-export injection types
```

## Dependencies

No new dependencies needed - uses existing `windows` crate.

## Step-by-Step Implementation

### Step 1: Define InjectionMethod Trait

**File:** `injector-core/src/injection/traits.rs`

```rust
//! Core injection traits and types.

use crate::{InjectionError, ProcessHandle};
use std::path::Path;

/// Result type for injection operations.
pub type InjectionResult<T> = Result<T, InjectionError>;

/// Common interface for all DLL injection methods.
///
/// Each injection technique (CreateRemoteThread, Manual Mapping, etc.)
/// implements this trait to provide a unified interface.
pub trait InjectionMethod {
    /// Inject a DLL into the target process.
    ///
    /// # Arguments
    /// * `handle` - Open process handle with required access rights
    /// * `dll_path` - Absolute path to the DLL file
    ///
    /// # Errors
    /// Returns `InjectionError` if injection fails for any reason.
    ///
    /// # Safety
    /// This function performs unsafe operations on the target process.
    /// The DLL must be compatible with the target process architecture.
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()>;

    /// Get the name of this injection method.
    fn name(&self) -> &'static str;

    /// Get the required process access rights for this method.
    fn required_access(&self) -> windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;
}

/// Validate a DLL path before injection.
///
/// Checks:
/// - Path is absolute
/// - File exists
/// - File has .dll extension
pub fn validate_dll_path(path: &Path) -> InjectionResult<()> {
    // Must be absolute path
    if !path.is_absolute() {
        return Err(InjectionError::RelativePath);
    }

    // File must exist
    if !path.exists() {
        return Err(InjectionError::DllNotFound(
            path.display().to_string()
        ));
    }

    // Should have .dll extension
    if path.extension().and_then(|s| s.to_str()) != Some("dll") {
        log::warn!("DLL path does not have .dll extension: {}", path.display());
    }

    Ok(())
}

/// Check if process is 32-bit or 64-bit.
///
/// Returns true if process is 64-bit, false if 32-bit.
pub fn is_process_64bit(handle: &ProcessHandle) -> InjectionResult<bool> {
    use windows::Win32::System::Threading::IsWow64Process;

    let mut is_wow64 = false;

    unsafe {
        IsWow64Process(handle.as_handle(), &mut is_wow64)
            .map_err(|_| InjectionError::Io(std::io::Error::last_os_error()))?;
    }

    // If running on 64-bit Windows:
    // - WoW64 process = 32-bit
    // - Non-WoW64 process = 64-bit
    #[cfg(target_pointer_width = "64")]
    {
        Ok(!is_wow64)
    }

    // If running on 32-bit Windows, all processes are 32-bit
    #[cfg(target_pointer_width = "32")]
    {
        Ok(false)
    }
}

/// Validate architecture compatibility between injector and target.
pub fn validate_architecture(handle: &ProcessHandle) -> InjectionResult<()> {
    let target_is_64bit = is_process_64bit(handle)?;
    let injector_is_64bit = cfg!(target_pointer_width = "64");

    if target_is_64bit != injector_is_64bit {
        return Err(InjectionError::ArchitectureMismatch {
            injector: if injector_is_64bit { "64-bit".into() } else { "32-bit".into() },
            target: if target_is_64bit { "64-bit".into() } else { "32-bit".into() },
        });
    }

    Ok(())
}
```

### Step 2: Implement Remote Memory Allocator

**File:** `injector-core/src/memory/allocator.rs`

```rust
//! Remote memory allocation with RAII cleanup.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::*;
use crate::InjectionError;

/// RAII wrapper for remotely allocated memory.
///
/// Automatically frees memory when dropped.
pub struct RemoteMemory {
    process: HANDLE,
    address: *mut u8,
    size: usize,
}

impl RemoteMemory {
    /// Allocate memory in the target process.
    ///
    /// # Arguments
    /// * `process` - Target process handle
    /// * `size` - Number of bytes to allocate
    /// * `protection` - Memory protection flags
    ///
    /// # Errors
    /// Returns `InjectionError::MemoryAllocationFailed` on failure.
    pub fn allocate(
        process: HANDLE,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<Self, InjectionError> {
        let address = unsafe {
            VirtualAllocEx(
                process,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                protection,
            )
        };

        if address.is_null() {
            return Err(InjectionError::MemoryAllocationFailed(
                std::io::Error::last_os_error()
            ));
        }

        log::debug!(
            "Allocated {} bytes at {:?} in remote process",
            size,
            address
        );

        Ok(Self {
            process,
            address: address as *mut u8,
            size,
        })
    }

    /// Get the address of the allocated memory.
    pub fn address(&self) -> *mut u8 {
        self.address
    }

    /// Get the size of the allocation.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Convert to raw pointer (for FFI).
    pub fn as_ptr(&self) -> *const std::ffi::c_void {
        self.address as *const std::ffi::c_void
    }
}

impl Drop for RemoteMemory {
    fn drop(&mut self) {
        unsafe {
            let result = VirtualFreeEx(
                self.process,
                self.address as *const std::ffi::c_void,
                0,
                MEM_RELEASE,
            );

            if let Err(e) = result {
                log::warn!(
                    "Failed to free remote memory at {:?}: {}",
                    self.address,
                    e
                );
            } else {
                log::debug!("Freed remote memory at {:?}", self.address);
            }
        }
    }
}

// Prevent RemoteMemory from being sent between threads
impl !Send for RemoteMemory {}
impl !Sync for RemoteMemory {}
```

### Step 3: Implement Memory Writer

**File:** `injector-core/src/memory/writer.rs`

```rust
//! Writing data to remote process memory.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use crate::InjectionError;

/// Write data to a remote process's memory.
///
/// # Arguments
/// * `process` - Target process handle
/// * `address` - Address to write to
/// * `data` - Data to write
///
/// # Errors
/// Returns `InjectionError::MemoryWriteFailed` if write fails.
///
/// # Safety
/// The caller must ensure:
/// - `address` is valid in the remote process
/// - Remote memory is large enough to hold `data`
/// - Remote memory has write permissions
pub fn write_memory(
    process: HANDLE,
    address: *mut u8,
    data: &[u8],
) -> Result<(), InjectionError> {
    let mut bytes_written = 0;

    unsafe {
        WriteProcessMemory(
            process,
            address as *const std::ffi::c_void,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            Some(&mut bytes_written),
        )
        .map_err(|_| InjectionError::MemoryWriteFailed(
            std::io::Error::last_os_error()
        ))?;
    }

    if bytes_written != data.len() {
        log::warn!(
            "Partial write: {} of {} bytes written",
            bytes_written,
            data.len()
        );
        return Err(InjectionError::MemoryWriteFailed(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Incomplete write operation"
            )
        ));
    }

    log::debug!(
        "Wrote {} bytes to {:?} in remote process",
        bytes_written,
        address
    );

    Ok(())
}

/// Write a wide string (UTF-16) to remote memory.
pub fn write_wide_string(
    process: HANDLE,
    address: *mut u8,
    text: &str,
) -> Result<(), InjectionError> {
    // Convert to UTF-16
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();

    // Write as bytes
    let bytes = unsafe {
        std::slice::from_raw_parts(
            wide.as_ptr() as *const u8,
            wide.len() * 2,
        )
    };

    write_memory(process, address, bytes)
}
```

### Step 4: Update Memory Module

**File:** `injector-core/src/memory/mod.rs`

```rust
//! Remote memory management operations.

pub mod allocator;
pub mod writer;

pub use allocator::RemoteMemory;
pub use writer::{write_memory, write_wide_string};
```

### Step 5: Implement CreateRemoteThread Injection

**File:** `injector-core/src/injection/create_remote_thread.rs`

```rust
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
                Some(std::mem::transmute(loadlib_addr)),
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

            match wait_result {
                WAIT_OBJECT_0 => {
                    log::debug!("Thread completed successfully");

                    // Get thread exit code (DLL module handle)
                    let mut exit_code = 0;
                    if GetExitCodeThread(thread_handle, &mut exit_code).is_ok() {
                        if exit_code == 0 {
                            log::error!("LoadLibraryW returned NULL - DLL failed to load");
                            return Err(InjectionError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "LoadLibraryW failed in target process"
                            )));
                        }
                        log::info!("DLL loaded at address: 0x{:X}", exit_code);
                    }
                }
                WAIT_TIMEOUT => {
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
```

### Step 6: Update Injection Module

**File:** `injector-core/src/injection/mod.rs`

```rust
//! DLL injection methods and utilities.

pub mod traits;
pub mod create_remote_thread;

pub use traits::{
    InjectionMethod,
    InjectionResult,
    validate_dll_path,
    validate_architecture,
    is_process_64bit,
};
pub use create_remote_thread::CreateRemoteThreadInjector;
```

### Step 7: Update Library Exports

**File:** `injector-core/src/lib.rs`

```rust
//! Core DLL injection library for Windows.
//!
//! This library provides multiple DLL injection methods for Windows processes.
//! All methods implement the `InjectionMethod` trait for a unified interface.

pub mod error;
pub mod process;
pub mod injection;
pub mod memory;
pub mod pe;
pub mod privilege;

// Re-export commonly used types
pub use error::{InjectionError, ProcessError};
pub use process::{ProcessEnumerator, ProcessHandle, ProcessInfo};
pub use injection::{InjectionMethod, CreateRemoteThreadInjector};
```

### Step 8: Update Error Types

**File:** `injector-core/src/error.rs` (add any missing variants)

```rust
use std::io;
use thiserror::Error;

/// Errors that can occur during process operations.
#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("Failed to create process snapshot")]
    SnapshotFailed(#[source] io::Error),

    #[error("Failed to enumerate processes")]
    EnumerationFailed(#[source] io::Error),

    #[error("Process not found: {0}")]
    ProcessNotFound(u32),

    #[error("Failed to open process handle")]
    OpenProcessFailed(#[source] io::Error),

    #[error("Invalid process handle")]
    InvalidHandle,
}

/// Errors that can occur during DLL injection.
#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("Process error: {0}")]
    ProcessError(#[from] ProcessError),

    #[error("DLL file not found: {0}")]
    DllNotFound(String),

    #[error("DLL path must be absolute")]
    RelativePath,

    #[error("Architecture mismatch: injector is {injector}, target is {target}")]
    ArchitectureMismatch { injector: String, target: String },

    #[error("Failed to allocate memory in target process")]
    MemoryAllocationFailed(#[source] io::Error),

    #[error("Failed to write to target process memory")]
    MemoryWriteFailed(#[source] io::Error),

    #[error("Failed to read from target process memory")]
    MemoryReadFailed(#[source] io::Error),

    #[error("Failed to create remote thread")]
    CreateThreadFailed(#[source] io::Error),

    #[error("LoadLibrary address not found")]
    LoadLibraryNotFound,

    #[error("NtCreateThreadEx function not found in ntdll.dll")]
    NtCreateThreadExNotFound,

    #[error("Failed to parse PE file: {0}")]
    PeParseError(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}
```

### Step 9: Run Tests

```bash
cd F:\Projects\Cheats\dllInjector
cargo test -p injector-core
cargo clippy -p injector-core
```

### Step 10: Create Integration Test

**File:** `injector-core/tests/integration_test.rs` (create tests/ directory)

```rust
//! Integration tests for DLL injection.
//!
//! Note: These tests require a test DLL and target process.

use injector_core::*;
use std::path::PathBuf;

#[test]
#[ignore] // Ignore by default - requires setup
fn test_inject_into_notepad() {
    // This test requires:
    // 1. Notepad.exe running
    // 2. Test DLL compiled (tests/fixtures/test.dll)
    // 3. Administrator privileges

    let processes = ProcessEnumerator::find_by_name("notepad.exe")
        .expect("Failed to enumerate processes");

    if processes.is_empty() {
        eprintln!("Notepad not running - skipping test");
        return;
    }

    let process = &processes[0];
    let injector = CreateRemoteThreadInjector::new();

    let handle = ProcessHandle::open(
        process.pid,
        injector.required_access(),
    ).expect("Failed to open process");

    let dll_path = PathBuf::from("F:\\Projects\\Cheats\\dllInjector\\tests\\fixtures\\test.dll");

    let result = injector.inject(&handle, &dll_path);
    assert!(result.is_ok(), "Injection failed: {:?}", result.err());
}
```

## Windows API Usage

### VirtualAllocEx
```rust
VirtualAllocEx(
    process,           // Target process handle
    None,              // Let Windows choose address
    size,              // Size in bytes
    MEM_COMMIT | MEM_RESERVE,  // Commit and reserve
    PAGE_READWRITE,    // Read/write protection
)
```

**Common Errors:**
- `ERROR_ACCESS_DENIED` - Need PROCESS_VM_OPERATION
- `ERROR_NOT_ENOUGH_MEMORY` - System out of memory

### WriteProcessMemory
```rust
WriteProcessMemory(
    process,           // Target process handle
    address,           // Remote address
    data.as_ptr(),     // Data to write
    data.len(),        // Number of bytes
    &mut bytes_written // Bytes actually written
)
```

**Common Errors:**
- `ERROR_ACCESS_DENIED` - Need PROCESS_VM_WRITE
- `ERROR_PARTIAL_COPY` - Some pages not writable

### CreateRemoteThread
```rust
CreateRemoteThread(
    process,           // Target process handle
    None,              // Default security
    0,                 // Default stack size
    thread_proc,       // Thread start address (LoadLibraryW)
    parameter,         // Thread parameter (DLL path)
    0,                 // Run immediately
    None,              // Don't need thread ID
)
```

**Common Errors:**
- `ERROR_ACCESS_DENIED` - Need PROCESS_CREATE_THREAD
- `ERROR_NOT_SUPPORTED` - Protected process

## Error Handling

### Expected Errors

1. **DLL Not Found**
   - Validate path before injection
   - Show clear error message to user

2. **Architecture Mismatch**
   - Check IsWow64Process
   - Prevent 32-bit injecting into 64-bit

3. **Access Denied**
   - May need SeDebugPrivilege (Phase 5)
   - Protected processes cannot be injected

4. **LoadLibrary Failed**
   - Check thread exit code
   - DLL may have missing dependencies

## Testing Checklist

- [ ] Code compiles without errors or warnings
- [ ] Unit tests pass
- [ ] Can get LoadLibraryW address
- [ ] DLL path validation works
- [ ] Architecture validation works
- [ ] Memory allocation/deallocation works
- [ ] Integration test works (with test DLL)

## Common Pitfalls

### 1. Relative DLL Paths
**Problem:** Relative paths resolve differently in target process
**Solution:** Always require absolute paths, validate with is_absolute()

### 2. Architecture Mismatch
**Problem:** Injecting 32-bit DLL into 64-bit process crashes
**Solution:** Check IsWow64Process before injection

### 3. Memory Leaks
**Problem:** Forgetting to free remote memory
**Solution:** Use RAII RemoteMemory wrapper

### 4. Thread Handle Leak
**Problem:** Not closing thread handle after CreateRemoteThread
**Solution:** Always close handle after waiting

### 5. LoadLibrary Failure
**Problem:** Thread succeeds but DLL doesn't load
**Solution:** Check thread exit code (0 = failure)

### 6. UTF-16 String Errors
**Problem:** Incorrect string encoding or missing null terminator
**Solution:** Use encode_utf16().chain(once(0))

## Completion Criteria

Phase 3 is complete when:
- ✅ InjectionMethod trait defined
- ✅ CreateRemoteThread injector implemented
- ✅ Memory allocation with RAII works
- ✅ DLL path validation complete
- ✅ Architecture validation complete
- ✅ All tests pass
- ✅ Integration test works with test DLL

## Git Commit

```bash
git add injector-core/src/injection/ injector-core/src/memory/
git add injector-core/tests/
git commit -m "feat: implement CreateRemoteThread injection method

- Define InjectionMethod trait for unified injection interface
- Implement RemoteMemory RAII wrapper for automatic cleanup
- Add memory writing utilities (write_memory, write_wide_string)
- Implement CreateRemoteThread injection with full error handling
- Add DLL path validation (absolute, exists, .dll extension)
- Add architecture validation (32-bit vs 64-bit compatibility)
- Include comprehensive unit tests for all components
- Add integration test framework with test fixture support

CreateRemoteThread injection fully functional.
Ready for Phase 4 UI implementation.

Follows docs/phases/phase-03-basic-injection.md
"
```

## Next Steps

Proceed to **Phase 4: UI Foundation** (docs/phases/phase-04-ui-foundation.md)

Phase 4 will implement:
- egui UI layout with panels
- Process list with search/filter
- Injection control panel
- Real-time log viewer
- Method selection

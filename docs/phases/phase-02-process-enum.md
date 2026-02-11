# Phase 2: Process Enumeration

**Status:** ⏳ Pending
**Estimated Time:** 4-6 hours
**Complexity:** Medium

## Phase Overview

Implement process discovery and management functionality. This phase creates the foundation for selecting injection targets by enumerating running processes, retrieving their information, and safely managing process handles.

## Objectives

- [ ] Implement ProcessEnumerator using CreateToolhelp32Snapshot
- [ ] Create ProcessInfo struct with PID, name, and executable path
- [ ] Implement RAII ProcessHandle wrapper with automatic cleanup
- [ ] Add filtering by process name and PID
- [ ] Write comprehensive error handling
- [ ] Create unit tests for process operations

## Prerequisites

- ✅ Phase 1: Project foundation complete
- ✅ Workspace compiles successfully
- Understanding of Windows process API
- Familiarity with RAII pattern in Rust

## Learning Resources

- [CreateToolhelp32Snapshot MSDN](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
- [Process32First/Next MSDN](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
- [OpenProcess MSDN](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [windows-rs Documentation](https://microsoft.github.io/windows-docs-rs/)

## File Structure

```
injector-core/src/
├── process/
│   ├── mod.rs              # Export public types
│   ├── info.rs             # ProcessInfo struct ← NEW
│   ├── enumerator.rs       # ProcessEnumerator impl ← NEW
│   └── handle.rs           # ProcessHandle RAII wrapper ← NEW
├── error.rs                # Already has ProcessError types
└── lib.rs                  # Re-export process types
```

## Dependencies

No new dependencies needed - uses existing `windows` crate features.

## Step-by-Step Implementation

### Step 1: Implement ProcessInfo Struct

**File:** `injector-core/src/process/info.rs`

```rust
use std::path::PathBuf;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID (PID)
    pub pid: u32,

    /// Process name (e.g., "notepad.exe")
    pub name: String,

    /// Full path to executable (if available)
    pub path: Option<PathBuf>,

    /// Parent process ID
    pub parent_pid: u32,

    /// Number of threads
    pub thread_count: u32,
}

impl ProcessInfo {
    /// Create ProcessInfo from Windows PROCESSENTRY32W structure.
    pub(crate) fn from_entry(entry: &PROCESSENTRY32W) -> Self {
        // Extract process name from wide string
        let name = {
            let len = entry.szExeFile.iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            String::from_utf16_lossy(&entry.szExeFile[..len])
        };

        Self {
            pid: entry.th32ProcessID,
            name,
            path: None, // Will be populated later if needed
            parent_pid: entry.th32ParentProcessID,
            thread_count: entry.cntThreads,
        }
    }

    /// Get the full path to the process executable.
    ///
    /// This requires opening the process handle, which may fail for
    /// protected processes without SeDebugPrivilege.
    pub fn try_get_path(&mut self) -> Result<Option<PathBuf>, crate::ProcessError> {
        use windows::Win32::System::ProcessStatus::*;
        use windows::Win32::System::Threading::*;
        use crate::process::ProcessHandle;

        // Try to open process with QUERY_LIMITED_INFORMATION
        let handle = ProcessHandle::open(
            self.pid,
            PROCESS_QUERY_LIMITED_INFORMATION,
        )?;

        // Get executable path
        let mut buffer = [0u16; 260]; // MAX_PATH
        let mut size = buffer.len() as u32;

        unsafe {
            if QueryFullProcessImageNameW(
                handle.as_handle(),
                PROCESS_NAME_WIN32,
                &mut buffer,
                &mut size,
            ).as_bool() {
                let path_str = String::from_utf16_lossy(&buffer[..size as usize]);
                self.path = Some(PathBuf::from(path_str));
                Ok(self.path.clone())
            } else {
                Ok(None)
            }
        }
    }
}

impl std::fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (PID: {})", self.name, self.pid)
    }
}
```

### Step 2: Implement ProcessHandle RAII Wrapper

**File:** `injector-core/src/process/handle.rs`

```rust
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
use crate::ProcessError;

/// RAII wrapper for a Windows process handle.
///
/// Automatically closes the handle when dropped, preventing leaks.
pub struct ProcessHandle {
    handle: HANDLE,
}

impl ProcessHandle {
    /// Open a process by PID with specified access rights.
    ///
    /// # Arguments
    /// * `pid` - Process ID to open
    /// * `rights` - Desired access rights (e.g., PROCESS_ALL_ACCESS)
    ///
    /// # Errors
    /// Returns `ProcessError::OpenProcessFailed` if the process cannot be opened.
    /// Common reasons:
    /// - Process doesn't exist
    /// - Insufficient privileges (need SeDebugPrivilege)
    /// - Protected process (anti-malware, etc.)
    pub fn open(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Result<Self, ProcessError> {
        let handle = unsafe { OpenProcess(rights, false, pid) };

        match handle {
            Ok(h) if h.is_invalid() => {
                Err(ProcessError::OpenProcessFailed(
                    std::io::Error::last_os_error()
                ))
            }
            Ok(h) => Ok(Self { handle: h }),
            Err(_) => Err(ProcessError::OpenProcessFailed(
                std::io::Error::last_os_error()
            )),
        }
    }

    /// Get the raw HANDLE.
    ///
    /// # Safety
    /// The returned handle is only valid as long as this ProcessHandle exists.
    pub fn as_handle(&self) -> HANDLE {
        self.handle
    }

    /// Check if the handle is valid.
    pub fn is_valid(&self) -> bool {
        !self.handle.is_invalid()
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

// Prevent ProcessHandle from being sent between threads
impl !Send for ProcessHandle {}
impl !Sync for ProcessHandle {}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

    #[test]
    fn test_open_current_process() {
        // Current process ID
        let pid = std::process::id();

        // Should be able to open our own process
        let handle = ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION);
        assert!(handle.is_ok());

        let handle = handle.unwrap();
        assert!(handle.is_valid());
    }

    #[test]
    fn test_open_invalid_pid() {
        // PID 0 is invalid
        let result = ProcessHandle::open(0, PROCESS_QUERY_INFORMATION);
        assert!(result.is_err());
    }
}
```

### Step 3: Implement ProcessEnumerator

**File:** `injector-core/src/process/enumerator.rs`

```rust
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::Foundation::CloseHandle;
use crate::{ProcessError, ProcessInfo};

/// Process enumeration utility.
pub struct ProcessEnumerator;

impl ProcessEnumerator {
    /// Enumerate all running processes.
    ///
    /// # Errors
    /// Returns `ProcessError::SnapshotFailed` if unable to create process snapshot.
    /// Returns `ProcessError::EnumerationFailed` if unable to iterate processes.
    pub fn enumerate() -> Result<Vec<ProcessInfo>, ProcessError> {
        // Create snapshot of all processes
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|_| ProcessError::SnapshotFailed(
                    std::io::Error::last_os_error()
                ))?
        };

        // Ensure snapshot is closed on scope exit
        let _snapshot_guard = SnapshotGuard(snapshot);

        // Initialize PROCESSENTRY32W structure
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // Get first process
        unsafe {
            Process32FirstW(snapshot, &mut entry)
                .map_err(|_| ProcessError::EnumerationFailed(
                    std::io::Error::last_os_error()
                ))?;
        }

        // Collect all processes
        let mut processes = Vec::new();

        loop {
            processes.push(ProcessInfo::from_entry(&entry));

            // Get next process
            if unsafe { Process32NextW(snapshot, &mut entry).is_err() } {
                break;
            }
        }

        log::debug!("Enumerated {} processes", processes.len());
        Ok(processes)
    }

    /// Find a process by PID.
    pub fn find_by_pid(pid: u32) -> Result<ProcessInfo, ProcessError> {
        let processes = Self::enumerate()?;
        processes.into_iter()
            .find(|p| p.pid == pid)
            .ok_or(ProcessError::ProcessNotFound(pid))
    }

    /// Find processes by name (case-insensitive).
    pub fn find_by_name(name: &str) -> Result<Vec<ProcessInfo>, ProcessError> {
        let processes = Self::enumerate()?;
        let name_lower = name.to_lowercase();

        Ok(processes.into_iter()
            .filter(|p| p.name.to_lowercase().contains(&name_lower))
            .collect())
    }
}

/// RAII guard for closing snapshot handle.
struct SnapshotGuard(windows::Win32::Foundation::HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_processes() {
        let processes = ProcessEnumerator::enumerate();
        assert!(processes.is_ok());

        let processes = processes.unwrap();
        assert!(!processes.is_empty(), "Should find at least one process");

        // Should find our own process
        let current_pid = std::process::id();
        let found = processes.iter().any(|p| p.pid == current_pid);
        assert!(found, "Should find current process in list");
    }

    #[test]
    fn test_find_by_pid() {
        let current_pid = std::process::id();
        let result = ProcessEnumerator::find_by_pid(current_pid);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.pid, current_pid);
    }

    #[test]
    fn test_find_by_name() {
        // Find processes with "exe" in name (should match most processes)
        let result = ProcessEnumerator::find_by_name("exe");
        assert!(result.is_ok());

        let processes = result.unwrap();
        assert!(!processes.is_empty(), "Should find processes with 'exe' in name");
    }

    #[test]
    fn test_find_invalid_pid() {
        let result = ProcessEnumerator::find_by_pid(9999999);
        assert!(result.is_err());
    }
}
```

### Step 4: Update Module Exports

**File:** `injector-core/src/process/mod.rs`

```rust
//! Process enumeration and management.

mod enumerator;
mod handle;
mod info;

pub use enumerator::ProcessEnumerator;
pub use handle::ProcessHandle;
pub use info::ProcessInfo;
```

### Step 5: Update Error Types (if needed)

**File:** `injector-core/src/error.rs`

Ensure `ProcessError` has all variants used above:

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

// ... rest of error types from Phase 1
```

### Step 6: Add Missing Windows Features

Update `injector-core/Cargo.toml` if needed:

```toml
[dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_Threading",
    "Win32_System_Memory",
    "Win32_System_LibraryLoader",
    "Win32_Security",
    "Win32_System_ProcessStatus",  # ← Add this if missing
] }
```

### Step 7: Run Tests

```bash
cd F:\Projects\Cheats\dllInjector
cargo test -p injector-core
```

**Expected output:**
```
running 6 tests
test process::enumerator::tests::test_enumerate_processes ... ok
test process::enumerator::tests::test_find_by_pid ... ok
test process::enumerator::tests::test_find_by_name ... ok
test process::enumerator::tests::test_find_invalid_pid ... ok
test process::handle::tests::test_open_current_process ... ok
test process::handle::tests::test_open_invalid_pid ... ok

test result: ok. 6 passed; 0 failed; 0 ignored
```

## Testing Checklist

- [ ] `cargo test -p injector-core` passes all tests
- [ ] Can enumerate processes without errors
- [ ] Find current process by PID works
- [ ] Find by name returns results
- [ ] ProcessHandle closes automatically (no leaks)
- [ ] Invalid PID returns appropriate error
- [ ] No clippy warnings

## Common Pitfalls

### 1. Wide String Conversion
**Problem:** PROCESSENTRY32W uses UTF-16 wide strings
**Solution:** Use `String::from_utf16_lossy()` for safe conversion

### 2. Handle Leaks
**Problem:** Forgetting to close snapshot handle
**Solution:** Use RAII guard pattern (SnapshotGuard)

### 3. Null Termination
**Problem:** Wide strings in szExeFile may not be fully used
**Solution:** Find null terminator position before conversion

### 4. Privilege Issues
**Problem:** QueryFullProcessImageNameW fails for system processes
**Solution:** Return Option<PathBuf> and handle access denied gracefully

### 5. Invalid Handle Checks
**Problem:** OpenProcess returns invalid handle but doesn't fail
**Solution:** Check both return value AND handle validity

## Completion Criteria

Phase 2 is complete when:
- ✅ All code compiles without errors
- ✅ All tests pass
- ✅ Can enumerate processes successfully
- ✅ ProcessHandle automatically cleans up
- ✅ Filtering by PID and name works
- ✅ Error handling is comprehensive
- ✅ No memory leaks (verified by tests)

## Git Commit

```bash
git add injector-core/src/process/
git commit -m "feat: implement process enumeration and management

- Add ProcessInfo struct with PID, name, path, and thread count
- Implement ProcessEnumerator using CreateToolhelp32Snapshot
- Create RAII ProcessHandle wrapper with automatic cleanup
- Add filtering by PID and name
- Include comprehensive error handling
- Write unit tests for all functionality

All tests passing. Ready for Phase 3 injection implementation.

Follows docs/phases/phase-02-process-enum.md
"
```

## Next Steps

Proceed to **Phase 3: Basic Injection** (docs/phases/phase-03-basic-injection.md)

Phase 3 will implement:
- InjectionMethod trait
- CreateRemoteThread injection method
- Memory allocation wrappers
- DLL path validation

# API Reference

Complete API documentation for the `injector-core` library.

## Overview

`injector-core` is a Rust library providing DLL injection functionality for Windows. It offers:

- Four distinct injection methods
- Process enumeration and management
- Memory operations for remote processes
- PE file parsing for manual mapping
- Privilege management
- Comprehensive error handling

**Target audience:** Developers integrating DLL injection into their own applications.

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
injector-core = { path = "../injector-core" }
windows = { version = "0.58", features = [
    "Win32_System_Threading",
    "Win32_Foundation",
] }
```

---

## Quick Example

```rust
use injector_core::*;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Enable debug privilege (required)
    PrivilegeManager::enable_debug_privilege()?;

    // 2. Find target process
    let processes = ProcessEnumerator::find_by_name("notepad")?;
    let target = processes.first().ok_or("Process not found")?;

    // 3. Open process handle
    let handle = ProcessHandle::open(
        target.pid,
        windows::Win32::System::Threading::PROCESS_ALL_ACCESS
    )?;

    // 4. Inject DLL
    let injector = CreateRemoteThreadInjector;
    injector.inject(&handle, Path::new(r"C:\test.dll"))?;

    println!("Injection successful!");
    Ok(())
}
```

---

## Module Documentation

### Re-exports

The following items are re-exported from `injector_core` root:

```rust
// Error types
pub use error::{InjectionError, ProcessError, PrivilegeError};

// Process management
pub use process::{ProcessEnumerator, ProcessHandle, ProcessInfo};

// Injection methods
pub use injection::{
    CreateRemoteThreadInjector,
    InjectionMethod,
    ManualMapInjector,
    NtCreateThreadExInjector,
    QueueUserApcInjector,
};

// Privilege management
pub use privilege::PrivilegeManager;
```

---

## `process` Module

Process enumeration and handle management.

### `ProcessEnumerator`

Enumerate and find running processes.

#### Methods

##### `enumerate() -> Result<Vec<ProcessInfo>, ProcessError>`

Enumerates all running processes on the system.

**Returns:**
- `Ok(Vec<ProcessInfo>)` - List of all processes
- `Err(ProcessError)` - If enumeration fails

**Example:**
```rust
let processes = ProcessEnumerator::enumerate()?;
for process in processes {
    println!("{} (PID: {})", process.name, process.pid);
}
```

---

##### `find_by_pid(pid: u32) -> Result<ProcessInfo, ProcessError>`

Finds a process by its process ID.

**Arguments:**
- `pid` - The process ID to search for

**Returns:**
- `Ok(ProcessInfo)` - The process with matching PID
- `Err(ProcessError::ProcessNotFound)` - If no such process exists

**Example:**
```rust
let process = ProcessEnumerator::find_by_pid(1234)?;
println!("Found: {}", process.name);
```

---

##### `find_by_name(name: &str) -> Result<Vec<ProcessInfo>, ProcessError>`

Finds all processes matching the given name (case-insensitive substring match).

**Arguments:**
- `name` - Process name or substring to search for

**Returns:**
- `Ok(Vec<ProcessInfo>)` - List of matching processes (may be empty)
- `Err(ProcessError)` - If enumeration fails

**Example:**
```rust
let processes = ProcessEnumerator::find_by_name("notepad")?;
if let Some(target) = processes.first() {
    println!("Found: {} (PID: {})", target.name, target.pid);
}
```

---

### `ProcessHandle`

RAII wrapper for Windows process handles. Automatically closes handle on drop.

#### Methods

##### `open(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Result<ProcessHandle, ProcessError>`

Opens a process with the specified access rights.

**Arguments:**
- `pid` - Process ID to open
- `rights` - Desired access rights (from `windows` crate)

**Returns:**
- `Ok(ProcessHandle)` - Successfully opened handle
- `Err(ProcessError::OpenProcessFailed)` - Failed to open process

**Example:**
```rust
use windows::Win32::System::Threading::{
    PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

let rights = PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE;

let handle = ProcessHandle::open(1234, rights)?;
```

---

##### `pid(&self) -> u32`

Returns the process ID associated with this handle.

**Example:**
```rust
let handle = ProcessHandle::open(1234, PROCESS_QUERY_INFORMATION)?;
assert_eq!(handle.pid(), 1234);
```

---

##### `as_handle(&self) -> HANDLE`

Returns the raw Windows handle.

**Safety:** Caller must ensure they don't use the handle after `ProcessHandle` is dropped.

---

##### `is_valid(&self) -> bool`

Checks if the handle is valid.

**Returns:**
- `true` - Handle is valid
- `false` - Handle is invalid

---

### `ProcessInfo`

Information about a process.

#### Fields

```rust
pub struct ProcessInfo {
    pub pid: u32,         // Process ID
    pub ppid: u32,        // Parent process ID
    pub name: String,     // Process name (e.g., "notepad.exe")
}
```

#### Trait Implementations

- `Display` - Formats as "process_name (PID: 1234)"
- `Debug` - Debug output
- `Clone` - Can be cloned

**Example:**
```rust
let process = ProcessEnumerator::find_by_pid(1234)?;
println!("{}", process);  // "notepad.exe (PID: 1234)"
```

---

## `injection` Module

DLL injection methods and utilities.

### `InjectionMethod` Trait

Common interface for all injection methods.

```rust
pub trait InjectionMethod {
    /// Inject a DLL into the target process
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()>;

    /// Get the name of this injection method
    fn name(&self) -> &'static str;

    /// Get the required process access rights
    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS;
}
```

---

### `CreateRemoteThreadInjector`

Classic injection via `CreateRemoteThread` API.

**Characteristics:**
- **Compatibility:** Excellent - works on all Windows versions
- **Stealth:** Low - well-known and easily detected
- **Complexity:** Simple
- **Reliability:** Very high

**Example:**
```rust
let injector = CreateRemoteThreadInjector;
injector.inject(&handle, Path::new(r"C:\test.dll"))?;
```

**How it works:**
1. Allocates memory in target process
2. Writes DLL path to allocated memory
3. Gets address of `LoadLibraryA`
4. Creates remote thread starting at `LoadLibraryA` with DLL path

**Required access rights:**
- `PROCESS_CREATE_THREAD`
- `PROCESS_QUERY_INFORMATION`
- `PROCESS_VM_OPERATION`
- `PROCESS_VM_READ`
- `PROCESS_VM_WRITE`

---

### `QueueUserApcInjector`

Injection via Asynchronous Procedure Call (APC).

**Characteristics:**
- **Compatibility:** Moderate - requires alertable thread
- **Stealth:** Good - less suspicious than CreateRemoteThread
- **Complexity:** Moderate
- **Reliability:** Moderate (depends on thread state)

**Example:**
```rust
let injector = QueueUserApcInjector;
injector.inject(&handle, Path::new(r"C:\test.dll"))?;
```

**How it works:**
1. Enumerates threads in target process
2. Allocates memory and writes DLL path
3. Queues `LoadLibraryA` as APC to all threads
4. DLL loads when any thread enters alertable state

**Best for:** GUI applications (usually have alertable threads)

**Warning:** May hang if target has no alertable threads!

**Required access rights:**
- `PROCESS_CREATE_THREAD`
- `PROCESS_QUERY_INFORMATION`
- `PROCESS_VM_OPERATION`
- `PROCESS_VM_READ`
- `PROCESS_VM_WRITE`

---

### `NtCreateThreadExInjector`

Injection via undocumented `NtCreateThreadEx` API.

**Characteristics:**
- **Compatibility:** Good - works on most Windows versions
- **Stealth:** Good - bypasses some user-mode hooks
- **Complexity:** Moderate
- **Reliability:** High

**Example:**
```rust
let injector = NtCreateThreadExInjector;
injector.inject(&handle, Path::new(r"C:\test.dll"))?;
```

**How it works:**
1. Dynamically loads `NtCreateThreadEx` from `ntdll.dll`
2. Allocates memory and writes DLL path
3. Creates remote thread using native API
4. Calls `LoadLibraryA` to load DLL

**Advantages over CreateRemoteThread:**
- Bypasses user-mode hooks on `CreateRemoteThread`
- More reliable in some scenarios

**Required access rights:**
- `PROCESS_CREATE_THREAD`
- `PROCESS_QUERY_INFORMATION`
- `PROCESS_VM_OPERATION`
- `PROCESS_VM_READ`
- `PROCESS_VM_WRITE`

---

### `ManualMapInjector`

Advanced injection via manual PE mapping.

**Characteristics:**
- **Compatibility:** Limited - doesn't support all DLLs
- **Stealth:** Excellent - bypasses PEB module list
- **Complexity:** High
- **Reliability:** Moderate (DLL-dependent)

**Example:**
```rust
let injector = ManualMapInjector;
injector.inject(&handle, Path::new(r"C:\test.dll"))?;
```

**How it works:**
1. Parses PE file structure
2. Allocates memory in target process
3. Maps sections manually
4. Resolves import table
5. Processes relocations
6. Calls DLL entry point directly

**Advantages:**
- Doesn't use `LoadLibrary` (bypasses hooks)
- Doesn't appear in PEB module list
- Maximum stealth

**Limitations:**
- **No TLS support** - DLLs with Thread Local Storage won't work
- **No delay-load support** - Delay-loaded imports not supported
- **DllMain restrictions** - Entry point must be compatible with manual mapping

**Required access rights:**
- `PROCESS_CREATE_THREAD`
- `PROCESS_QUERY_INFORMATION`
- `PROCESS_VM_OPERATION`
- `PROCESS_VM_READ`
- `PROCESS_VM_WRITE`

---

### Helper Functions

#### `validate_dll_path(path: &Path) -> InjectionResult<()>`

Validates a DLL path before injection.

**Checks:**
- Path is absolute (not relative)
- File exists
- File has `.dll` extension (warns if not)

**Example:**
```rust
use injector_core::injection::validate_dll_path;

validate_dll_path(Path::new(r"C:\test.dll"))?;
```

---

#### `is_process_64bit(handle: &ProcessHandle) -> InjectionResult<bool>`

Checks if a process is 32-bit or 64-bit.

**Returns:**
- `Ok(true)` - Process is 64-bit
- `Ok(false)` - Process is 32-bit
- `Err(InjectionError)` - Failed to determine

**Example:**
```rust
use injector_core::injection::is_process_64bit;

let is_64bit = is_process_64bit(&handle)?;
println!("Process is {}-bit", if is_64bit { 64 } else { 32 });
```

---

#### `validate_architecture(handle: &ProcessHandle) -> InjectionResult<()>`

Validates that injector and target have matching architectures.

**Returns:**
- `Ok(())` - Architectures match
- `Err(InjectionError::ArchitectureMismatch)` - Mismatched (64-bit injector, 32-bit target, etc.)

**Example:**
```rust
use injector_core::injection::validate_architecture;

validate_architecture(&handle)?;
```

---

## `privilege` Module

Windows privilege management.

### `PrivilegeManager`

Manages process privileges.

#### Methods

##### `enable_debug_privilege() -> Result<(), PrivilegeError>`

Enables `SeDebugPrivilege` for the current process.

**Required for:** Opening most processes for injection.

**Returns:**
- `Ok(())` - Privilege successfully enabled
- `Err(PrivilegeError)` - Failed to enable privilege

**Example:**
```rust
PrivilegeManager::enable_debug_privilege()?;
```

**Note:** Requires administrator privileges. Will fail if not running as admin.

---

##### `try_enable_debug_privilege() -> bool`

Attempts to enable debug privilege without returning an error.

**Returns:**
- `true` - Successfully enabled
- `false` - Failed to enable

**Example:**
```rust
if PrivilegeManager::try_enable_debug_privilege() {
    println!("Debug privilege enabled");
} else {
    println!("Failed to enable debug privilege (not admin?)");
}
```

---

##### `is_administrator() -> Result<bool, PrivilegeError>`

Checks if the current process is running with administrator privileges.

**Returns:**
- `Ok(true)` - Running as administrator
- `Ok(false)` - Not running as administrator
- `Err(PrivilegeError)` - Failed to determine

**Example:**
```rust
if PrivilegeManager::is_administrator()? {
    println!("Running as administrator");
} else {
    println!("Not administrator - some features may fail");
}
```

---

## `error` Module

Error types for the library.

### `InjectionError`

Errors that can occur during injection.

**Variants:**

```rust
pub enum InjectionError {
    /// DLL file not found at specified path
    DllNotFound(String),

    /// DLL path must be absolute, not relative
    RelativePath,

    /// Architecture mismatch (32-bit injector, 64-bit target, etc.)
    ArchitectureMismatch {
        injector: String,
        target: String,
    },

    /// Memory allocation in target process failed
    AllocationFailed(std::io::Error),

    /// Failed to write to target process memory
    WriteFailed(std::io::Error),

    /// Failed to create remote thread
    ThreadCreationFailed(std::io::Error),

    /// LoadLibrary call in target process failed
    LoadLibraryFailed,

    /// PE file parsing error (manual map)
    PeParseError(String),

    /// Import resolution failed (manual map)
    ImportResolutionFailed(String),

    /// Process-related error
    ProcessError(ProcessError),

    /// Generic I/O error
    Io(std::io::Error),
}
```

**Trait implementations:**
- `std::error::Error`
- `std::fmt::Display`
- `std::fmt::Debug`
- `From<ProcessError>` - Convert from ProcessError
- `From<std::io::Error>` - Convert from IO errors

---

### `ProcessError`

Errors related to process operations.

**Variants:**

```rust
pub enum ProcessError {
    /// Failed to create process snapshot
    SnapshotFailed(std::io::Error),

    /// Failed to enumerate processes
    EnumerationFailed(std::io::Error),

    /// Process with given PID not found
    ProcessNotFound(u32),

    /// Failed to open process
    OpenProcessFailed(std::io::Error),

    /// Thread enumeration failed
    ThreadEnumFailed(std::io::Error),

    /// Failed to read process memory
    ReadMemoryFailed(std::io::Error),

    /// Failed to write process memory
    WriteMemoryFailed(std::io::Error),
}
```

**Trait implementations:**
- `std::error::Error`
- `std::fmt::Display`
- `std::fmt::Debug`

---

### `PrivilegeError`

Errors related to privilege operations.

**Variants:**

```rust
pub enum PrivilegeError {
    /// Failed to open process token
    OpenTokenFailed(std::io::Error),

    /// Failed to lookup privilege value
    LookupPrivilegeFailed(std::io::Error),

    /// Failed to adjust token privileges
    AdjustPrivilegeFailed(std::io::Error),

    /// Failed to check admin status
    AdminCheckFailed(std::io::Error),
}
```

**Trait implementations:**
- `std::error::Error`
- `std::fmt::Display`
- `std::fmt::Debug`

---

## Type Aliases

### `InjectionResult<T>`

Convenience type alias for injection operations.

```rust
pub type InjectionResult<T> = Result<T, InjectionError>;
```

**Example:**
```rust
fn my_inject_function() -> InjectionResult<()> {
    // ... injection logic
    Ok(())
}
```

---

## Complete Example

Full example demonstrating all major features:

```rust
use injector_core::*;
use std::path::Path;
use windows::Win32::System::Threading::{
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check admin status
    if !PrivilegeManager::is_administrator()? {
        eprintln!("Warning: Not running as administrator");
        eprintln!("Some processes may not be accessible");
    }

    // Enable debug privilege
    match PrivilegeManager::enable_debug_privilege() {
        Ok(_) => println!("✓ Debug privilege enabled"),
        Err(e) => {
            eprintln!("✗ Failed to enable debug privilege: {}", e);
            eprintln!("Run as administrator!");
            return Err(e.into());
        }
    }

    // Find target process
    println!("Searching for target process...");
    let processes = ProcessEnumerator::find_by_name("notepad")?;

    if processes.is_empty() {
        eprintln!("Process not found. Start notepad.exe first!");
        return Ok(());
    }

    let target = &processes[0];
    println!("✓ Found: {} (PID: {})", target.name, target.pid);

    // Open process handle
    println!("Opening process handle...");
    let access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;

    let handle = ProcessHandle::open(target.pid, access)?;
    println!("✓ Handle opened");

    // Validate architecture
    println!("Validating architecture...");
    injection::validate_architecture(&handle)?;
    println!("✓ Architecture compatible");

    // Prepare DLL path
    let dll_path = Path::new(r"C:\path\to\test_dll.dll");
    injection::validate_dll_path(dll_path)?;
    println!("✓ DLL path validated");

    // Select and use injection method
    println!("Injecting DLL...");

    // Try CreateRemoteThread first (most compatible)
    let injector = CreateRemoteThreadInjector;
    match injector.inject(&handle, dll_path) {
        Ok(_) => {
            println!("✓ Injection successful using {}!", injector.name());
        }
        Err(e) => {
            eprintln!("✗ Injection failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
```

---

## Platform Requirements

- **Operating System:** Windows 10 or later
- **Architecture:** x86-64 (x86 may work but untested)
- **Privileges:** Administrator required for most operations
- **Dependencies:** Windows API via `windows` crate

---

## Thread Safety

**Process enumeration:** Thread-safe ✅
**ProcessHandle:** Send (can move between threads) ✅
**Injection methods:** Thread-safe, but only one injection per process recommended ⚠️

---

## Performance Considerations

**Process enumeration:**
- Takes ~10-50ms depending on number of processes
- Cache results if enumerating frequently

**Injection performance:**
- CreateRemoteThread: ~5-20ms
- QueueUserAPC: ~10-50ms (waits for alertable state)
- NtCreateThreadEx: ~5-20ms
- Manual Map: ~50-200ms (parses PE, more complex)

---

## Best Practices

1. **Always check admin status** before attempting injection
2. **Enable debug privilege** before opening processes
3. **Validate architecture** before injection to avoid crashes
4. **Use absolute DLL paths** - relative paths will fail
5. **Handle errors gracefully** - log details for debugging
6. **Start with CreateRemoteThread** - most compatible method
7. **Test with simple DLLs first** - use `test_dll.dll`
8. **Don't inject into system processes** - high crash risk

---

## See Also

- [User Guide](user-guide.md) - GUI application guide
- [Architecture](architecture.md) - Technical design details
- [Examples](../injector-core/examples/README.md) - Working code examples
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

---

**Last Updated:** 2026-02-12
**API Version:** 0.1.0

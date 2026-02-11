# API Reference

> **Note:** This is a stub. Full API documentation will be completed in Phase 11.

Public API documentation for `injector-core` library.

## Overview

The `injector-core` crate provides a reusable library for DLL injection on Windows. It can be used in CLI tools, GUI applications, or embedded in other projects.

## Quick Start

```rust
use injector_core::{ProcessEnumerator, InjectionMethod};
use injector_core::injection::CreateRemoteThreadInjector;
use std::path::Path;

// Enumerate processes
let processes = ProcessEnumerator::enumerate()?;

// Find target process
let target = ProcessEnumerator::find_by_name("notepad.exe")?;
let target_pid = target[0].pid;

// Perform injection
let injector = CreateRemoteThreadInjector::new();
let dll_path = Path::new("C:\\path\\to\\dll.dll");
injector.inject(target_pid, dll_path)?;
```

## Modules

### `process`

Process enumeration and management.

**Types:**
- `ProcessEnumerator` - Enumerate running processes
- `ProcessHandle` - RAII wrapper for process handles
- `ProcessInfo` - Information about a process

**See Phase 2 documentation for details.**

### `injection`

DLL injection methods.

**Trait:**
- `InjectionMethod` - Common interface for all injection methods

**Implementations:**
- `CreateRemoteThreadInjector` - Classic injection method
- `ManualMappingInjector` - Stealth injection via manual mapping
- `QueueUserApcInjector` - APC-based injection
- `NtCreateThreadExInjector` - Undocumented NT API injection

**See Phase 3, 6, and 7 documentation for details.**

### `memory`

Memory operations in remote processes.

**Types:**
- `RemoteMemory` - Allocated memory in remote process
- `MemoryWriter` - Write to remote process memory
- `MemoryReader` - Read from remote process memory

**See Phase 3 and 6 documentation for details.**

### `pe`

PE file parsing for manual mapping.

**Types:**
- `PeParser` - Parse PE files
- `SectionInfo` - PE section information
- `ImportDescriptor` - Import table entries
- `RelocationBlock` - Relocation information

**See Phase 6 documentation for details.**

### `privilege`

Windows privilege management.

**Types:**
- `PrivilegeManager` - Manage process privileges
- Methods: `enable_debug_privilege()`, `is_admin()`

**See Phase 5 documentation for details.**

### `error`

Error types.

**Enums:**
- `ProcessError` - Process-related errors
- `InjectionError` - Injection-related errors

All errors implement `std::error::Error`.

## Full Documentation

Full API reference with examples will be added in Phase 11.

For now, see:
- Source code documentation comments
- Phase implementation guides
- Architecture documentation

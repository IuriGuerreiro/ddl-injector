# Architecture Overview

This document describes the high-level architecture of the DLL Injector project.

## System Design

The DLL Injector is built as a **Cargo workspace** with two main crates that follow a clean separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    injector-ui                          │
│                  (egui application)                     │
│  ┌──────────────┬──────────────┬──────────────┐        │
│  │ Process List │ Injection    │ Log Viewer   │        │
│  │ Component    │ Controls     │ Component    │        │
│  └──────┬───────┴──────┬───────┴──────┬───────┘        │
│         │              │              │                 │
│         └──────────────┼──────────────┘                 │
│                        ↓                                │
│              ┌─────────────────────┐                    │
│              │  InjectorApp State  │                    │
│              └──────────┬──────────┘                    │
└───────────────────────────┼────────────────────────────┘
                            │
                            ↓ (uses)
┌─────────────────────────────────────────────────────────┐
│                  injector-core                          │
│                (reusable library)                       │
│  ┌─────────────┬─────────────┬─────────────────────┐   │
│  │  Process    │  Injection  │  Memory & PE        │   │
│  │  Management │  Methods    │  Operations         │   │
│  └─────────────┴─────────────┴─────────────────────┘   │
│                                                          │
│  • ProcessEnumerator  • InjectionMethod trait           │
│  • ProcessHandle      • CreateRemoteThread              │
│  • PrivilegeManager   • ManualMapping                   │
│                       • QueueUserAPC                    │
│                       • NtCreateThreadEx                │
└─────────────────────────────────────────────────────────┘
                            │
                            ↓ (calls)
┌─────────────────────────────────────────────────────────┐
│              Windows API (windows crate)                │
│  • Process Management: CreateToolhelp32Snapshot         │
│  • Memory Operations: VirtualAllocEx, WriteProcessMemory│
│  • Thread Creation: CreateRemoteThread, QueueUserAPC    │
│  • Privileges: AdjustTokenPrivileges                    │
└─────────────────────────────────────────────────────────┘
```

## Core Design Principles

### 1. Separation of Concerns

**injector-core:**
- Pure Rust library with zero UI dependencies
- All injection logic, process management, and Windows API interaction
- Can be reused by CLI tools, other UIs, or embedded in other projects
- Comprehensive error handling with custom error types
- Fully testable in isolation

**injector-ui:**
- egui-based graphical interface
- Consumes `injector-core` as a library dependency
- Handles user interaction, visualization, and configuration
- Bridges core library to visual components

### 2. Trait-Based Injection System

All injection methods implement the `InjectionMethod` trait:

```rust
pub trait InjectionMethod {
    fn inject(&self, target_pid: u32, dll_path: &Path) -> Result<(), InjectionError>;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
}
```

**Benefits:**
- Easy to add new injection methods without modifying existing code
- UI can enumerate and display methods dynamically
- Each method is independently testable
- Clean abstraction that hides implementation details

**Implementations:**
1. `CreateRemoteThreadInjector` - Classic method using CreateRemoteThread
2. `ManualMappingInjector` - Stealth method with manual PE mapping
3. `QueueUserApcInjector` - APC-based injection
4. `NtCreateThreadExInjector` - Undocumented NT API method

### 3. RAII and Safe Resource Management

All Windows handles are wrapped in RAII structs:

```rust
pub struct ProcessHandle {
    handle: HANDLE,
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}
```

This ensures:
- No handle leaks even on error paths
- Automatic cleanup when objects go out of scope
- Prevents use-after-free bugs
- Type-safe handle usage

### 4. Comprehensive Error Handling

Using `thiserror` for structured errors:

```rust
#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("Process not found: {0}")]
    ProcessNotFound(u32),

    #[error("Failed to allocate memory in target process")]
    MemoryAllocationFailed(#[source] io::Error),

    #[error("Architecture mismatch: injector is {injector_arch}, target is {target_arch}")]
    ArchitectureMismatch {
        injector_arch: String,
        target_arch: String,
    },
    // ... more variants
}
```

Benefits:
- Clear error messages for debugging
- Error context preserved through the stack
- Easy to display user-friendly messages in UI

## Module Organization

### injector-core/src/

```
injector-core/src/
├── lib.rs              # Public API exports
├── error.rs            # Centralized error types
│
├── process/            # Process management
│   ├── mod.rs
│   ├── enumerator.rs   # Process enumeration
│   ├── handle.rs       # RAII process handle wrapper
│   └── info.rs         # ProcessInfo struct
│
├── injection/          # Injection methods
│   ├── mod.rs
│   ├── traits.rs       # InjectionMethod trait
│   ├── create_remote_thread.rs
│   ├── manual_map.rs
│   ├── queue_user_apc.rs
│   └── nt_create_thread.rs
│
├── memory/             # Memory operations
│   ├── mod.rs
│   ├── allocator.rs    # VirtualAllocEx wrapper
│   ├── writer.rs       # WriteProcessMemory wrapper
│   └── reader.rs       # ReadProcessMemory wrapper
│
├── pe/                 # PE file parsing (for manual mapping)
│   ├── mod.rs
│   ├── parser.rs       # DOS/NT header parsing
│   ├── sections.rs     # Section enumeration
│   ├── imports.rs      # Import table resolution
│   └── relocations.rs  # Base relocation handling
│
└── privilege/          # Privilege elevation
    ├── mod.rs
    └── manager.rs      # SeDebugPrivilege elevation
```

### injector-ui/src/

```
injector-ui/src/
├── main.rs             # Application entry point
├── app.rs              # InjectorApp (egui::App implementation)
├── config.rs           # Configuration persistence
│
└── ui/                 # UI components
    ├── mod.rs
    ├── process_list.rs    # Process browser panel
    ├── injection_panel.rs # Injection controls
    ├── log_viewer.rs      # Real-time log display
    └── settings.rs        # Settings panel
```

## Data Flow

### Injection Flow

1. **User selects process** (UI → ProcessList component)
2. **User selects DLL** (UI → file picker dialog)
3. **User chooses method** (UI → dropdown)
4. **User clicks "Inject"** (UI → InjectorApp state)
5. **App validates inputs** (UI layer validation)
6. **App calls core library** (UI → injector-core)
   ```rust
   let injector = CreateRemoteThreadInjector::new();
   injector.inject(selected_pid, &dll_path)?;
   ```
7. **Core performs injection** (injector-core → Windows API)
   - Open process handle
   - Allocate memory in target
   - Write DLL path
   - Create remote thread
8. **Result returned to UI** (injector-core → UI)
9. **UI updates log viewer** (success/failure message)

### Configuration Flow

1. **App starts** → Load config from `%APPDATA%/dllInjector/config.json`
2. **User changes settings** → Update in-memory config
3. **App closes** → Save config to disk
4. **Config includes:**
   - Recent DLLs (last 10)
   - Recent processes (last 10)
   - Window size/position
   - Default injection method
   - Log level

## Threading Model

### UI Thread (Main)
- Runs egui event loop
- Handles user input
- Updates UI components
- **Does NOT block** on long operations

### Injection Operations
- Currently **synchronous** (blocks UI thread)
- Future enhancement: Use async/channels for non-blocking injection
  ```rust
  // Future design
  std::thread::spawn(move || {
      let result = injector.inject(pid, dll_path);
      tx.send(result).unwrap();
  });
  ```

## Security Considerations

### Privilege Requirements

Many injection targets require **SeDebugPrivilege**:
- System processes
- Protected processes
- Processes running as different users

The `PrivilegeManager` attempts to enable this privilege at startup.

### Architecture Validation

Prevents common mistakes:
- Cannot inject 32-bit DLL into 64-bit process
- Cannot inject 64-bit DLL into 32-bit process
- Validation happens before injection attempt

### Error Handling

All Windows API calls are checked for errors:
```rust
let handle = unsafe { OpenProcess(rights, false, pid) };
if handle.is_invalid() {
    return Err(InjectionError::OpenProcessFailed(io::Error::last_os_error()));
}
```

## Extensibility Points

### Adding New Injection Methods

1. Implement the `InjectionMethod` trait
2. Add new file to `injector-core/src/injection/`
3. Export from `injector-core/src/injection/mod.rs`
4. UI automatically picks up the new method (if using dynamic enumeration)

### Adding New UI Components

1. Create new module in `injector-ui/src/ui/`
2. Implement rendering logic
3. Call from `InjectorApp::update()` method

### Adding New Configuration Options

1. Add fields to `AppConfig` struct
2. Mark with `#[serde(default)]` for backwards compatibility
3. Add UI controls in settings panel

## Dependencies

### Core Dependencies (injector-core)
- `windows = "0.58"` - Windows API bindings
- `thiserror = "2.0"` - Error handling
- `log = "0.4"` - Logging facade

### UI Dependencies (injector-ui)
- `egui = "0.30"` - Immediate mode GUI
- `eframe = "0.30"` - egui framework
- `anyhow = "1.1"` - Error handling for application layer
- `serde = "1.0"` - Config serialization
- `rfd = "0.15"` - Native file dialogs
- `env_logger = "0.11"` - Logging implementation

## Performance Considerations

### Process Enumeration
- Called on-demand (not continuous polling)
- Caches results until user clicks "Refresh"
- Filters applied in-memory (fast)

### Memory Operations
- Direct Windows API calls (minimal overhead)
- No unnecessary allocations
- Proper cleanup on all code paths

### UI Rendering
- egui is immediate mode (redraws each frame)
- Minimal state storage
- Efficient for debug UIs with dynamic content

## Testing Strategy

### Unit Tests (injector-core)
- Test each module in isolation
- Mock Windows API calls where needed
- Cover error paths

### Integration Tests
- Use test DLL and target process
- Verify end-to-end injection
- Test all injection methods

### Manual Testing (injector-ui)
- Visual verification
- Interaction testing
- Cross-platform checks (different Windows versions)

## Build Configuration

### Debug Builds
- Full symbols for debugging
- No optimizations
- Verbose logging enabled

### Release Builds
- Full optimizations
- Smaller binary size
- Minimal logging

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
```

## Future Enhancements

Potential improvements beyond Phase 11:

1. **Async Injection** - Non-blocking UI during injection
2. **Multiple Injection Queuing** - Batch operations
3. **DLL Unloading** - Remove injected DLLs
4. **Process Monitoring** - Real-time status updates
5. **Custom Shellcode** - Advanced users can provide shellcode
6. **Scripting API** - Lua/Python bindings for automation
7. **CLI Interface** - Command-line tool using same core library

## Conclusion

The architecture prioritizes:
- **Modularity** - Clean separation between core and UI
- **Safety** - RAII and proper error handling
- **Extensibility** - Easy to add new injection methods
- **Testability** - Core library fully testable
- **Maintainability** - Clear module boundaries and documentation

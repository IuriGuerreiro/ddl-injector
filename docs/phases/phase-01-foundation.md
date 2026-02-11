# Phase 1: Project Foundation

**Status:** ⏳ Pending
**Estimated Time:** 4-6 hours
**Complexity:** Low

## Phase Overview

Establish the Cargo workspace structure with two crates (`injector-core` and `injector-ui`), add all necessary dependencies, and create the basic module skeleton. This phase sets up the technical foundation for all future development.

## Objectives

- [ ] Create Cargo workspace with two crates
- [ ] Add all dependencies (windows, egui, thiserror, etc.)
- [ ] Create module structure with empty files
- [ ] Verify workspace compiles successfully
- [ ] Set up proper error handling foundation
- [ ] Configure release build optimizations

## Prerequisites

- ✅ Phase 0: Documentation complete
- Rust toolchain installed (`rustc --version` works)
- Windows 10/11 development environment
- Code editor (VS Code, RustRover, etc.)

## Learning Resources

- [Cargo Workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)
- [windows-rs Crate](https://github.com/microsoft/windows-rs)
- [egui Documentation](https://docs.rs/egui/latest/egui/)

## File Structure

```
dllInjector/
├── Cargo.toml                          # Workspace definition
├── .gitignore                          # Already created in Phase 0
├── docs/                               # Already created in Phase 0
├── injector-core/
│   ├── Cargo.toml                      # Core library manifest
│   └── src/
│       ├── lib.rs                      # Library root, public exports
│       ├── error.rs                    # Centralized error types
│       ├── process/
│       │   ├── mod.rs                  # Process module exports
│       │   ├── enumerator.rs           # (stub)
│       │   ├── handle.rs               # (stub)
│       │   └── info.rs                 # (stub)
│       ├── injection/
│       │   ├── mod.rs                  # Injection module exports
│       │   ├── traits.rs               # (stub)
│       │   ├── create_remote_thread.rs # (stub)
│       │   ├── manual_map.rs           # (stub)
│       │   ├── queue_user_apc.rs       # (stub)
│       │   └── nt_create_thread.rs     # (stub)
│       ├── memory/
│       │   ├── mod.rs                  # Memory operations exports
│       │   ├── allocator.rs            # (stub)
│       │   ├── writer.rs               # (stub)
│       │   └── reader.rs               # (stub)
│       ├── pe/
│       │   ├── mod.rs                  # PE parsing exports (stub)
│       │   ├── parser.rs               # (stub)
│       │   ├── sections.rs             # (stub)
│       │   ├── imports.rs              # (stub)
│       │   └── relocations.rs          # (stub)
│       └── privilege/
│           ├── mod.rs                  # Privilege module exports
│           └── manager.rs              # (stub)
└── injector-ui/
    ├── Cargo.toml                      # UI application manifest
    └── src/
        ├── main.rs                     # Application entry point
        ├── app.rs                      # InjectorApp struct (stub)
        ├── config.rs                   # Configuration (stub)
        └── ui/
            ├── mod.rs                  # UI module exports
            ├── process_list.rs         # (stub)
            ├── injection_panel.rs      # (stub)
            ├── log_viewer.rs           # (stub)
            └── settings.rs             # (stub)
```

## Dependencies

### Core Library (injector-core)

```toml
[dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_Threading",
    "Win32_System_Memory",
    "Win32_System_LibraryLoader",
    "Win32_Security",
] }
thiserror = "2.0"
log = "0.4"
```

### UI Application (injector-ui)

```toml
[dependencies]
injector-core = { path = "../injector-core" }
egui = "0.30"
eframe = { version = "0.30", default-features = false, features = [
    "default_fonts",
    "glow",
    "persistence",
] }
anyhow = "1.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rfd = "0.15"
env_logger = "0.11"
```

## Step-by-Step Implementation

### Step 1: Create Workspace Root

Create `F:\Projects\Cheats\dllInjector\Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "injector-core",
    "injector-ui",
]

[profile.dev]
opt-level = 0
debug = true

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

**Explanation:**
- `resolver = "2"` - Use Cargo's new feature resolver
- `members` - List of workspace crates
- `profile.release` - Aggressive optimizations for smaller binary
- `strip = true` - Remove debug symbols in release
- `panic = "abort"` - Smaller binary, faster panics

**Verification:**
```bash
cd F:\Projects\Cheats\dllInjector
cargo --version  # Should show Rust version
```

### Step 2: Create injector-core Crate

```bash
cd F:\Projects\Cheats\dllInjector
cargo new --lib injector-core
```

Create `F:\Projects\Cheats\dllInjector\injector-core\Cargo.toml`:

```toml
[package]
name = "injector-core"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "Core DLL injection library for Windows"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourusername/dllInjector"

[dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_Threading",
    "Win32_System_Memory",
    "Win32_System_LibraryLoader",
    "Win32_Security",
] }
thiserror = "2.0"
log = "0.4"

[dev-dependencies]
# Test dependencies will be added in Phase 10
```

### Step 3: Create Core Module Structure

Create empty module files with basic structure:

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
pub use injection::InjectionMethod;
```

**File:** `injector-core/src/error.rs`
```rust
//! Centralized error types for the injection library.

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

Create stub files:
```bash
# Create stub files (empty for now)
cd F:\Projects\Cheats\dllInjector\injector-core\src

# Process module stubs
mkdir process
echo "// Process enumerator implementation (Phase 2)" > process/enumerator.rs
echo "// RAII process handle wrapper (Phase 2)" > process/handle.rs
echo "// Process information struct (Phase 2)" > process/info.rs

# Injection module stubs
mkdir injection
echo "// Injection method trait (Phase 3)" > injection/traits.rs
echo "// CreateRemoteThread implementation (Phase 3)" > injection/create_remote_thread.rs
echo "// Manual mapping implementation (Phase 6)" > injection/manual_map.rs
echo "// QueueUserAPC implementation (Phase 7)" > injection/queue_user_apc.rs
echo "// NtCreateThreadEx implementation (Phase 7)" > injection/nt_create_thread.rs
echo "pub mod traits;" > injection/mod.rs

# Memory module stubs
mkdir memory
echo "// Memory allocator (Phase 3)" > memory/allocator.rs
echo "// Memory writer (Phase 3)" > memory/writer.rs
echo "// Memory reader (Phase 6)" > memory/reader.rs
echo "pub mod allocator; pub mod writer; pub mod reader;" > memory/mod.rs

# PE module stubs
mkdir pe
echo "// PE parser (Phase 6)" > pe/parser.rs
echo "// Section mapping (Phase 6)" > pe/sections.rs
echo "// Import resolution (Phase 6)" > pe/imports.rs
echo "// Relocation handling (Phase 6)" > pe/relocations.rs
echo "pub mod parser; pub mod sections; pub mod imports; pub mod relocations;" > pe/mod.rs

# Privilege module stubs
mkdir privilege
echo "// Privilege manager (Phase 5)" > privilege/manager.rs
echo "pub mod manager;" > privilege/mod.rs
```

### Step 4: Create injector-ui Crate

```bash
cd F:\Projects\Cheats\dllInjector
cargo new --bin injector-ui
```

Create `F:\Projects\Cheats\dllInjector\injector-ui\Cargo.toml`:

```toml
[package]
name = "injector-ui"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "GUI for DLL injection using egui"

[dependencies]
injector-core = { path = "../injector-core" }
egui = "0.30"
eframe = { version = "0.30", default-features = false, features = [
    "default_fonts",
    "glow",
    "persistence",
] }
anyhow = "1.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rfd = "0.15"
env_logger = "0.11"
log = "0.4"

[[bin]]
name = "injector"
path = "src/main.rs"
```

### Step 5: Create UI Module Structure

**File:** `injector-ui/src/main.rs`
```rust
//! DLL Injector GUI Application

use eframe::egui;

mod app;
mod config;
mod ui;

use app::InjectorApp;

fn main() -> Result<(), eframe::Error> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    log::info!("Starting DLL Injector v{}", env!("CARGO_PKG_VERSION"));

    // Configure native options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("DLL Injector"),
        ..Default::default()
    };

    // Run the application
    eframe::run_native(
        "DLL Injector",
        options,
        Box::new(|cc| Ok(Box::new(InjectorApp::new(cc)))),
    )
}
```

**File:** `injector-ui/src/app.rs`
```rust
//! Main application state and logic.

use eframe::egui;

pub struct InjectorApp {
    // Application state will be added in Phase 4
}

impl InjectorApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            // Initialize state
        }
    }
}

impl eframe::App for InjectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("DLL Injector");
            ui.label("UI will be implemented in Phase 4");
        });
    }
}
```

**File:** `injector-ui/src/config.rs`
```rust
//! Application configuration and persistence.
//! Implementation in Phase 8.
```

**File:** `injector-ui/src/ui/mod.rs`
```rust
//! UI components.
//! Implementation in Phase 4.

pub mod process_list;
pub mod injection_panel;
pub mod log_viewer;
pub mod settings;
```

Create stub UI component files:
```bash
cd F:\Projects\Cheats\dllInjector\injector-ui\src
mkdir ui
echo "// Process list component (Phase 4)" > ui/process_list.rs
echo "// Injection control panel (Phase 4)" > ui/injection_panel.rs
echo "// Log viewer component (Phase 4)" > ui/log_viewer.rs
echo "// Settings panel (Phase 8)" > ui/settings.rs
```

### Step 6: Verify Workspace Compiles

```bash
cd F:\Projects\Cheats\dllInjector
cargo build --workspace
```

**Expected output:**
```
   Compiling windows_x86_64_msvc v0.58.0
   Compiling windows-sys v0.59.0
   Compiling egui v0.30.0
   ...
   Compiling injector-core v0.1.0 (F:\Projects\Cheats\dllInjector\injector-core)
   Compiling injector-ui v0.1.0 (F:\Projects\Cheats\dllInjector\injector-ui)
    Finished dev [unoptimized + debuginfo] target(s) in XX.XXs
```

**If errors occur:**
- Check Cargo.toml syntax
- Verify all module files exist
- Ensure proper module declarations in mod.rs files

### Step 7: Test Basic UI Launch

```bash
cargo run -p injector-ui
```

**Expected:** Window opens with "DLL Injector" heading and "UI will be implemented in Phase 4" message.

**If window doesn't open:**
- Check Windows firewall
- Verify graphics drivers are up to date
- Check egui/eframe version compatibility

### Step 8: Create README.md

Create `F:\Projects\Cheats\dllInjector\README.md`:

```markdown
# DLL Injector

A multi-method DLL injector for Windows built in Rust with an egui UI.

## Features

- **Multiple Injection Methods:**
  - CreateRemoteThread (Classic)
  - Manual Mapping (Stealth)
  - QueueUserAPC (APC-based)
  - NtCreateThreadEx (Undocumented)

- **Modern UI:**
  - egui-based graphical interface
  - Process browser with search
  - Real-time logging
  - Configuration persistence

- **Safe and Reliable:**
  - Rust memory safety guarantees
  - Comprehensive error handling
  - RAII resource management

## Status

🚧 **Work in Progress** - Currently in Phase 1 (Foundation)

See [docs/README.md](docs/README.md) for full documentation.

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release -p injector-ui
```

## Project Structure

- `injector-core/` - Core injection library (reusable)
- `injector-ui/` - egui-based GUI application
- `docs/` - Comprehensive documentation

## Legal Disclaimer

This tool is for **authorized testing and educational purposes only**.

See [docs/legal-disclaimer.md](docs/legal-disclaimer.md) for full legal information.

## License

MIT OR Apache-2.0
```

## Testing Checklist

- [ ] `cargo build --workspace` succeeds without errors
- [ ] `cargo build --workspace --release` succeeds
- [ ] `cargo run -p injector-ui` launches window
- [ ] All module files created
- [ ] No compilation warnings (run `cargo clippy`)
- [ ] File structure matches documented layout

## Common Pitfalls

### 1. Windows Crate Features
**Problem:** Missing Windows API features causes compile errors
**Solution:** Add required features to windows dependency in Cargo.toml

### 2. Module Declaration Mismatch
**Problem:** Module declared in mod.rs but file doesn't exist
**Solution:** Ensure all modules declared in mod.rs have corresponding .rs files

### 3. Workspace Member Path Issues
**Problem:** injector-ui can't find injector-core
**Solution:** Verify path = "../injector-core" in injector-ui/Cargo.toml

### 4. egui Version Compatibility
**Problem:** egui and eframe versions mismatch
**Solution:** Use same version number for both (0.30)

### 5. Stub Files Empty
**Problem:** Empty .rs files cause compilation errors
**Solution:** Add at least a comment to each stub file

## Completion Criteria

Phase 1 is complete when:
- ✅ Workspace compiles without errors
- ✅ Both crates (core + ui) build successfully
- ✅ UI application launches and shows window
- ✅ All module files exist (even if stubs)
- ✅ Dependencies correctly configured
- ✅ README.md created
- ✅ No clippy warnings

## Git Commit

```bash
git add .
git commit -m "feat: initialize workspace with cargo structure and dependencies

- Create Cargo workspace with injector-core library and injector-ui binary
- Add all dependencies: windows, egui, eframe, thiserror, anyhow, serde, rfd
- Create module structure with stub files for all planned modules
- Implement basic error types in injector-core/src/error.rs
- Set up egui application skeleton that compiles and runs
- Configure release profile with aggressive optimizations
- Add comprehensive README.md

The workspace compiles and UI launches successfully.
All stub files ready for implementation in subsequent phases.

Follows docs/phases/phase-01-foundation.md
"
```

## Next Steps

Proceed to **Phase 2: Process Enumeration** (docs/phases/phase-02-process-enum.md)

Phase 2 will implement:
- Process enumeration using CreateToolhelp32Snapshot
- RAII process handle wrapper
- ProcessInfo struct with PID, name, and path
- Filtering capabilities

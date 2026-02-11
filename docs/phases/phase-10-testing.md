# Phase 10: Comprehensive Testing

**Status:** ⏳ Pending
**Estimated Time:** 4-6 hours
**Complexity:** Medium

## Phase Overview

Create a comprehensive test suite including unit tests, integration tests, and test fixtures. Write tests for all injection methods, PE parsing, process enumeration, and error handling. Create test DLLs with various characteristics.

## Objectives

- [ ] Write unit tests for all modules
- [ ] Create integration tests for injection
- [ ] Build test DLL fixtures (32-bit and 64-bit)
- [ ] Test error conditions and edge cases
- [ ] Add CI/CD configuration (optional)
- [ ] Measure code coverage
- [ ] Document testing procedures

## Prerequisites

- ✅ Phase 9: Logging complete
- All features implemented
- Understanding of Rust testing

## Learning Resources

- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Integration Tests](https://doc.rust-lang.org/book/ch11-03-test-organization.html#integration-tests)
- [cargo test](https://doc.rust-lang.org/cargo/commands/cargo-test.html)

## File Structure

```
injector-core/
├── src/
│   └── (existing modules with #[cfg(test)])
└── tests/
    ├── integration_test.rs        # Integration tests ← NEW
    └── fixtures/
        ├── test_dll_x64/          # 64-bit test DLL ← NEW
        ├── test_dll_x86/          # 32-bit test DLL ← NEW
        └── sample_pe.dll          # Sample for PE tests ← NEW
```

## Dependencies

Add test dependencies to `injector-core/Cargo.toml`:

```toml
[dev-dependencies]
tempfile = "3.8"  # For temporary files
```

## Step-by-Step Implementation

### Step 1: Create Test DLL (64-bit)

**File:** `injector-core/tests/fixtures/test_dll_x64/Cargo.toml`

```toml
[package]
name = "test_dll_x64"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_SystemServices"
] }
```

**File:** `injector-core/tests/fixtures/test_dll_x64/src/lib.rs`

```rust
use std::fs::OpenOptions;
use std::io::Write;
use windows::Win32::Foundation::*;
use windows::Win32::System::SystemServices::*;

static mut LOAD_COUNT: u32 = 0;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            unsafe { LOAD_COUNT += 1; }

            // Write marker file to prove injection worked
            let _ = std::panic::catch_unwind(|| {
                let temp_dir = std::env::temp_dir();
                let marker_file = temp_dir.join("dll_injector_test_marker.txt");

                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&marker_file)
                    .unwrap();

                writeln!(file, "Test DLL loaded (64-bit)").unwrap();
                writeln!(file, "Timestamp: {:?}", std::time::SystemTime::now()).unwrap();
                writeln!(file, "Load count: {}", unsafe { LOAD_COUNT }).unwrap();
            });

            TRUE
        }
        DLL_PROCESS_DETACH => TRUE,
        _ => TRUE,
    }
}

/// Exported function for testing GetProcAddress.
#[no_mangle]
pub extern "C" fn test_exported_function() -> i32 {
    42
}
```

### Step 2: Build Test DLLs

Create build script `injector-core/tests/build_fixtures.bat`:

```batch
@echo off
echo Building test fixtures...

cd tests\fixtures\test_dll_x64
cargo build --release
copy target\release\test_dll_x64.dll ..\test_dll_x64.dll

echo Test fixtures built successfully!
```

### Step 3: Integration Tests

**File:** `injector-core/tests/integration_test.rs`

```rust
//! Integration tests for DLL injection.
//!
//! These tests require administrator privileges and a running target process.

use injector_core::*;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// Helper to get test DLL path.
fn test_dll_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("test_dll_x64.dll");
    path
}

/// Helper to check if marker file was created.
fn check_marker_file() -> bool {
    let temp_dir = std::env::temp_dir();
    let marker_file = temp_dir.join("dll_injector_test_marker.txt");
    marker_file.exists()
}

/// Helper to clear marker file.
fn clear_marker_file() {
    let temp_dir = std::env::temp_dir();
    let marker_file = temp_dir.join("dll_injector_test_marker.txt");
    let _ = std::fs::remove_file(marker_file);
}

#[test]
#[ignore] // Run with: cargo test -- --ignored --test-threads=1
fn test_create_remote_thread_injection() {
    // Start notepad as test target
    let mut notepad = Command::new("notepad.exe")
        .spawn()
        .expect("Failed to start notepad");

    // Give it time to initialize
    std::thread::sleep(Duration::from_millis(500));

    let pid = notepad.id();

    // Clear any existing marker
    clear_marker_file();

    // Perform injection
    let injector = CreateRemoteThreadInjector::new();
    let dll_path = test_dll_path();

    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process");

    let result = injector.inject(&handle, &dll_path);

    // Verify success
    assert!(result.is_ok(), "Injection failed: {:?}", result.err());

    // Give DLL time to write marker
    std::thread::sleep(Duration::from_millis(100));

    // Check marker file exists
    assert!(check_marker_file(), "Marker file not created");

    // Cleanup
    notepad.kill().ok();
}

#[test]
#[ignore]
fn test_manual_map_injection() {
    let mut notepad = Command::new("notepad.exe")
        .spawn()
        .expect("Failed to start notepad");

    std::thread::sleep(Duration::from_millis(500));

    let pid = notepad.id();
    clear_marker_file();

    let injector = ManualMapInjector::new();
    let dll_path = test_dll_path();

    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process");

    let result = injector.inject(&handle, &dll_path);

    assert!(result.is_ok(), "Manual map failed: {:?}", result.err());

    std::thread::sleep(Duration::from_millis(100));
    assert!(check_marker_file(), "Marker file not created");

    notepad.kill().ok();
}

#[test]
fn test_process_enumeration() {
    let processes = ProcessEnumerator::enumerate();
    assert!(processes.is_ok());

    let processes = processes.unwrap();
    assert!(!processes.is_empty());

    // Should find our own process
    let current_pid = std::process::id();
    let found = processes.iter().any(|p| p.pid == current_pid);
    assert!(found, "Should find current process");
}

#[test]
fn test_find_process_by_name() {
    // Find processes with "exe" in name
    let result = ProcessEnumerator::find_by_name("exe");
    assert!(result.is_ok());

    let processes = result.unwrap();
    assert!(!processes.is_empty());
}

#[test]
fn test_validate_dll_path() {
    use injector_core::injection::validate_dll_path;
    use std::path::Path;

    // Relative path should fail
    let result = validate_dll_path(Path::new("test.dll"));
    assert!(result.is_err());

    // Non-existent path should fail
    let result = validate_dll_path(Path::new("C:\\nonexistent\\test.dll"));
    assert!(result.is_err());
}

#[test]
fn test_architecture_validation() {
    use injector_core::injection::is_process_64bit;

    // Test our own process
    let handle = ProcessHandle::open(
        std::process::id(),
        windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION,
    ).expect("Failed to open current process");

    let result = is_process_64bit(&handle);
    assert!(result.is_ok());

    #[cfg(target_pointer_width = "64")]
    assert!(result.unwrap(), "Should be 64-bit");

    #[cfg(target_pointer_width = "32")]
    assert!(!result.unwrap(), "Should be 32-bit");
}

#[test]
fn test_pe_parser() {
    use injector_core::pe::PeFile;

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        eprintln!("Test DLL not found, skipping PE parser test");
        return;
    }

    let result = PeFile::from_file(&dll_path);
    assert!(result.is_ok(), "Failed to parse PE: {:?}", result.err());

    let pe = result.unwrap();

    // Verify PE structure
    assert!(pe.is_64bit);
    assert!(pe.entry_point() != 0);
    assert!(!pe.sections.is_empty());

    // Should have common sections
    let section_names: Vec<String> = pe.sections.iter()
        .map(|s| s.name_str())
        .collect();

    assert!(section_names.iter().any(|n| n.contains("text")));
}

#[test]
fn test_privilege_manager() {
    use injector_core::PrivilegeManager;

    // Test administrator detection
    let is_admin = PrivilegeManager::is_administrator();
    assert!(is_admin.is_ok());

    println!("Running as administrator: {}", is_admin.unwrap());

    // Test privilege elevation (may fail if not admin)
    let result = PrivilegeManager::enable_debug_privilege();

    if result.is_err() {
        println!("SeDebugPrivilege not granted (expected if not admin)");
    }
}
```

### Step 4: Unit Tests for PE Parser

**File:** `injector-core/src/pe/parser.rs` (add tests)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_header_validation() {
        let header = ImageDosHeader {
            e_magic: ImageDosHeader::MAGIC,
            e_lfanew: 0x100,
            ..unsafe { std::mem::zeroed() }
        };

        assert!(header.is_valid());

        let bad_header = ImageDosHeader {
            e_magic: 0x1234, // Wrong magic
            ..unsafe { std::mem::zeroed() }
        };

        assert!(!bad_header.is_valid());
    }

    #[test]
    fn test_section_name_extraction() {
        let section = ImageSectionHeader {
            name: *b".text\0\0\0",
            ..unsafe { std::mem::zeroed() }
        };

        assert_eq!(section.name_str(), ".text");
    }
}
```

### Step 5: Add Test Documentation

**File:** `injector-core/tests/README.md`

```markdown
# Integration Tests

## Running Tests

### Unit Tests (no privileges required)
```bash
cargo test -p injector-core
```

### Integration Tests (requires administrator)
```bash
# Run as administrator
cargo test -p injector-core -- --ignored --test-threads=1
```

### Build Test Fixtures
```bash
cd injector-core/tests
.\build_fixtures.bat
```

## Test Fixtures

- `test_dll_x64.dll` - 64-bit test DLL that writes a marker file
- `test_dll_x86.dll` - 32-bit test DLL (optional)

## Marker File

Tests verify injection by checking for:
`%TEMP%\dll_injector_test_marker.txt`

## Test Coverage

Run with coverage:
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html --output-dir coverage
```
```

### Step 6: Add CI Configuration (Optional)

**File:** `.github/workflows/test.yml` (if using GitHub)

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest

    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true

      - name: Build
        run: cargo build --workspace --verbose

      - name: Run unit tests
        run: cargo test --workspace --verbose

      - name: Build test fixtures
        run: |
          cd injector-core/tests
          .\build_fixtures.bat
```

## Testing Checklist

- [ ] All unit tests pass
- [ ] Integration tests pass (with admin)
- [ ] Test DLLs build correctly
- [ ] PE parser tests pass
- [ ] Process enumeration tests pass
- [ ] Error condition tests pass
- [ ] Code coverage > 70%

## Common Pitfalls

### 1. Administrator Privileges
**Problem:** Integration tests fail without admin
**Solution:** Use #[ignore] and document requirement

### 2. Test Isolation
**Problem:** Tests interfere with each other
**Solution:** Use --test-threads=1 for integration tests

### 3. Marker File Cleanup
**Problem:** Previous test runs leave marker files
**Solution:** Clear marker before each test

### 4. Process Lifetime
**Problem:** Target process terminates too quickly
**Solution:** Keep process handle until test completes

## Completion Criteria

- ✅ Unit tests for all modules
- ✅ Integration tests for injection
- ✅ Test fixtures created
- ✅ Test documentation complete
- ✅ All tests passing
- ✅ Coverage measured

## Git Commit

```bash
git add injector-core/tests/
git commit -m "test: add comprehensive test suite

- Create integration tests for all injection methods
- Build test DLL fixtures (64-bit)
- Add unit tests for PE parser, process enum, etc.
- Include test documentation and procedures
- Add CI configuration for automated testing

Test coverage complete.

Follows docs/phases/phase-10-testing.md
"
```

## Next Steps

Proceed to **Phase 11: Polish** (docs/phases/phase-11-polish.md)

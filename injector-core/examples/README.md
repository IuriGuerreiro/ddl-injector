# DLL Injector Examples

This directory contains working examples demonstrating how to use the `injector-core` library in your own projects.

## Prerequisites

Before running these examples, ensure you have:

1. **Rust toolchain** installed (1.70 or later)
2. **Windows 10/11** (64-bit recommended)
3. **Administrator privileges** (required for most injection operations)
4. **Test DLL** built (see Building Test DLL section below)

## Examples Overview

### 1. Basic Injection (`basic_injection.rs`)

**Purpose:** Simple, straightforward DLL injection using CreateRemoteThread.

**Features:**
- Command-line argument parsing
- Process finding by name
- Debug privilege elevation
- Error handling with helpful messages
- Step-by-step progress output

**Usage:**
```bash
cargo run --example basic_injection -- <process_name> <dll_path>
```

**Example:**
```bash
# Inject into Notepad
cargo run --example basic_injection -- notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll
```

**Best for:**
- Learning the basics
- Quick testing
- Maximum compatibility

---

### 2. Custom Injector (`custom_injector.rs`)

**Purpose:** Advanced example demonstrating all 4 injection methods with runtime selection.

**Features:**
- Select injection method via command-line
- Comparison of all techniques
- Trait object usage pattern
- Method-specific pros/cons display

**Usage:**
```bash
cargo run --example custom_injector -- <method> <process_name> <dll_path>
```

**Methods:**
- `crt` - CreateRemoteThread (most compatible)
- `apc` - QueueUserAPC (stealthier)
- `nt` - NtCreateThreadEx (native API)
- `manual` - Manual Map (advanced)

**Examples:**
```bash
# CreateRemoteThread injection
cargo run --example custom_injector -- crt notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll

# QueueUserAPC injection (requires alertable thread)
cargo run --example custom_injector -- apc calc.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll

# NtCreateThreadEx injection
cargo run --example custom_injector -- nt notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll

# Manual Map injection
cargo run --example custom_injector -- manual notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll
```

**Best for:**
- Comparing injection techniques
- Understanding trade-offs
- Advanced injection scenarios

---

## Building Test DLL

Before running examples, build the test DLL:

```bash
# Build test DLL (debug)
cargo build -p test-dll

# Build test DLL (release - recommended)
cargo build -p test-dll --release
```

The DLL will be located at:
- Debug: `target\debug\test_dll.dll`
- Release: `target\release\test_dll.dll`

**What the test DLL does:**
- Creates a MessageBox when injected
- Shows the injection method used
- Logs to a file in `%TEMP%` directory
- Safe for testing (no harmful operations)

---

## Safe Test Targets

Use these processes for testing (safe and won't cause system issues):

### Recommended Test Processes

1. **Notepad** (`notepad.exe`)
   - Lightweight, single-threaded
   - Easy to start and close
   - Best for basic testing

2. **Calculator** (`calc.exe`)
   - Simple GUI application
   - Works with all injection methods

3. **Paint** (`mspaint.exe`)
   - Standard Windows application
   - Good for testing GUI interactions

### Starting a Test Process

```bash
# Start Notepad
start notepad.exe

# Start Calculator (Windows 10+)
start calc.exe

# Start Paint
start mspaint.exe
```

### ⚠️ Processes to AVOID

**Never inject into:**
- System processes (csrss.exe, smss.exe, services.exe)
- Security processes (lsass.exe, winlogon.exe)
- Windows Explorer (explorer.exe) - can crash your desktop
- Antivirus processes - will trigger alerts
- Online games - violates ToS, causes bans

---

## Expected Output

### Successful Injection

```
DLL Injector - Basic Example
=============================
Target Process: notepad.exe
DLL Path: F:\Projects\Cheats\dllInjector\target\release\test_dll.dll

[1/5] Elevating to Debug privileges...
    ✓ Debug privilege enabled
[2/5] Searching for process 'notepad.exe'...
    ✓ Found process: notepad.exe (PID: 12345)
[3/5] Opening handle to process...
    ✓ Process handle opened successfully
[4/5] Validating DLL path...
    ✓ DLL path validated: F:\Projects\Cheats\dllInjector\target\release\test_dll.dll
[5/5] Injecting DLL using CreateRemoteThread method...
    ✓ DLL injected successfully!
✅ Injection completed successfully!
```

You should see a MessageBox appear in the target process!

### Common Errors

**Process not found:**
```
❌ Injection failed: Process 'notepad.exe' not found. Is it running?
```
**Solution:** Start the target process first.

**Access denied:**
```
❌ Injection failed: Failed to open process: Access denied. Run as administrator?
```
**Solution:** Run the example with administrator privileges.

**DLL not found:**
```
❌ Injection failed: DLL file not found: C:\path\to\test_dll.dll
```
**Solution:** Build the test DLL first, verify the path is correct and absolute.

**Architecture mismatch:**
```
❌ Injection failed: Architecture mismatch - 64-bit injector, 32-bit target
```
**Solution:** Ensure injector and target process have the same architecture (both 64-bit or both 32-bit).

---

## Running as Administrator

Most injection operations require administrator privileges.

### Windows Terminal / PowerShell
```powershell
# Right-click Windows Terminal → "Run as Administrator"
cd F:\Projects\Cheats\dllInjector
cargo run --example basic_injection -- notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll
```

### Command Prompt
```cmd
# Right-click Command Prompt → "Run as Administrator"
cd F:\Projects\Cheats\dllInjector
cargo run --example basic_injection -- notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll
```

---

## Debugging

Enable verbose logging with the `RUST_LOG` environment variable:

### PowerShell
```powershell
$env:RUST_LOG="debug"
cargo run --example basic_injection -- notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll
```

### Command Prompt
```cmd
set RUST_LOG=debug
cargo run --example basic_injection -- notepad.exe F:\Projects\Cheats\dllInjector\target\release\test_dll.dll
```

This will show detailed logging from the injection process, including Windows API calls and error details.

---

## Integration into Your Project

To use the injector library in your own Rust project:

### 1. Add Dependency

Add to your `Cargo.toml`:
```toml
[dependencies]
injector-core = { path = "../injector-core" }
windows = { version = "0.58", features = [
    "Win32_System_Threading",
    "Win32_Foundation",
] }
```

### 2. Basic Usage Pattern

```rust
use injector_core::{
    CreateRemoteThreadInjector,
    InjectionMethod,
    PrivilegeManager,
    ProcessEnumerator,
    ProcessHandle,
};
use std::path::Path;
use windows::Win32::System::Threading::{
    PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable debug privilege
    PrivilegeManager::enable_debug_privilege()?;

    // Find target process
    let processes = ProcessEnumerator::find_by_name("notepad")?;
    let target = processes.first()
        .ok_or("Process not found")?;

    // Open process handle
    let access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;
    let handle = ProcessHandle::open(target.pid, access)?;

    // Inject DLL
    let injector = CreateRemoteThreadInjector;
    let dll_path = Path::new(r"C:\path\to\your.dll");
    injector.inject(&handle, dll_path)?;

    println!("Injection successful!");
    Ok(())
}
```

---

## Troubleshooting

For more detailed troubleshooting, see:
- [Troubleshooting Guide](../docs/troubleshooting.md)
- [Testing Guide](../docs/TESTING.md)
- [Architecture Documentation](../docs/architecture.md)

---

## Legal Notice

**⚠️ Read before using these examples!**

These examples are for **educational purposes only**. By using this software, you agree to:

- Only inject into processes you own or have explicit permission to modify
- Never use for cheating in online games or bypassing security systems
- Comply with all applicable laws and Terms of Service
- Accept full responsibility for your actions

See [Legal Disclaimer](../docs/legal-disclaimer.md) for complete details.

---

## Questions or Issues?

- Check the [main README](../README.md)
- Review [API Reference](../docs/api-reference.md)
- Open an issue on GitHub
- Read [Contributing Guidelines](../CONTRIBUTING.md)

Happy (responsible) injecting!

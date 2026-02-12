# DLL Injector - User Guide

Complete guide for using the DLL Injector GUI application.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [UI Components](#ui-components)
4. [Injection Methods](#injection-methods)
5. [Common Workflows](#common-workflows)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)
8. [Advanced Usage](#advanced-usage)

---

## Installation

### Prerequisites

**System Requirements:**
- Windows 10 or Windows 11 (64-bit recommended)
- Administrator privileges (required for process injection)
- 50 MB free disk space
- Microsoft Visual C++ Redistributable 2015-2022

**For building from source:**
- Rust 1.70 or later ([Install from rustup.rs](https://rustup.rs/))
- Visual Studio Build Tools 2019 or later

### Download Pre-built Binary

1. Download the latest release from GitHub releases
2. Extract the ZIP file to a folder (e.g., `C:\Tools\DLLInjector`)
3. Right-click `injector.exe` → "Run as administrator"

### Build from Source

```bash
# Clone the repository
git clone https://github.com/username/dllInjector.git
cd dllInjector

# Build release version
cargo build --workspace --release

# Executables are in target/release/
# - injector.exe (GUI application)
# - injector-cli.exe (command-line tool)
# - test_dll.dll (test DLL for safe testing)
```

---

## Quick Start

**Your first injection in 5 steps:**

1. **Launch as Administrator**
   - Right-click `injector.exe` → "Run as administrator"
   - The app MUST run as admin to access other processes

2. **Start a test process**
   - Open Notepad (Press Win+R, type `notepad`, press Enter)
   - Leave Notepad running

3. **Select the target process**
   - In the left panel, search for "notepad"
   - Click on "notepad.exe" in the process list

4. **Select your DLL**
   - In the center panel, click "Browse..."
   - Navigate to `target\release\test_dll.dll`
   - Click "Open"

5. **Inject!**
   - Click the "Inject DLL" button
   - You should see a MessageBox appear in Notepad!
   - Check the log panel at the bottom for confirmation

✅ **Success!** You've performed your first DLL injection.

---

## UI Components

The application interface consists of four main areas:

### 1. Menu Bar (Top)

**File Menu:**
- **Refresh Processes** - Manually refresh the process list
- **Settings** - Open settings dialog
- **Exit** - Close the application

**Help Menu:**
- **About** - Show version and license information

### 2. Process List (Left Panel)

**Features:**
- **Search box** - Filter processes by name (case-insensitive)
- **Process table** - Shows all running processes with:
  - Process name (e.g., "notepad.exe")
  - Process ID (PID)
  - Parent process ID (PPID)
- **Selection** - Click to select target process
- **Auto-refresh** - Updates every 5 seconds
- **Manual refresh** - Use File → Refresh Processes

**Tips:**
- Type in the search box to quickly find your target
- Look for the green highlight on the selected process
- Multiple instances of the same program will show separately

### 3. Injection Panel (Center)

**Status Indicators:**

At the top, you'll see your privilege status:
- ✅ **Administrator** - Running with admin rights (required)
- ❌ **Not Administrator** - Run as admin to enable injection
- ✅ **SeDebugPrivilege** - Debug privilege enabled (required for most processes)
- ❌ **SeDebugPrivilege** - Not enabled (check admin status)

**DLL Path Selection:**

- **Text field** - Shows the selected DLL path
- **Browse button** - Opens file picker dialog (.dll filter)
- **Recent DLLs** - Dropdown showing recently used DLLs for quick access

**Method Selection:**

Choose from 4 injection methods (see [Injection Methods](#injection-methods) section):
- CreateRemoteThread (default, most compatible)
- Manual Map (advanced, stealthier)
- QueueUserAPC (requires alertable thread)
- NtCreateThreadEx (native API, more reliable)

**Inject Button:**

- **Enabled** - When process and DLL are selected, and you have privileges
- **Disabled** - Missing requirements (will show error message)
- Click to perform the injection

**Error Display:**

If injection fails, an error message appears in red:
- "No process selected" - Select a process first
- "No DLL selected" - Choose a DLL file first
- "Access denied" - Run as administrator
- "Architecture mismatch" - 32/64-bit incompatibility
- Other errors - Check the log panel for details

### 4. Log Viewer (Bottom Panel)

**Features:**
- **Real-time logging** - See injection progress live
- **Timestamp** - Each log entry shows date and time
- **Log levels** - Color-coded severity:
  - 🔵 INFO - General information
  - 🟡 WARN - Warnings (non-critical issues)
  - 🔴 ERROR - Errors (failures)
- **Auto-scroll** - Automatically scrolls to newest entries
- **Search/Filter** - Find specific log entries
- **Clear button** - Clear all log entries

**Persistent Logs:**

Logs are also saved to files:
- Location: `%APPDATA%\DLLInjector\logs\`
- Format: `injector_YYYY-MM-DD_HH-MM-SS.log`
- Rotation: Keeps last 10 log files

### 5. Settings Window

Access via File → Settings. Configure:

**General Settings:**
- **Preferred injection method** - Default method for new sessions
- **Process filter** - Remember your search filter
- **Recent DLLs list size** - How many recent DLLs to remember

**Appearance:**
- **Theme** - Light or dark mode (if implemented)
- **Font size** - Adjust UI font size

**Advanced:**
- **Auto-refresh interval** - Process list refresh rate
- **Log level** - Minimum severity to display

Settings are saved automatically to:
`%APPDATA%\DLLInjector\config.json`

---

## Injection Methods

Choose the right injection technique for your use case:

### Comparison Table

| Method | Compatibility | Stealth | Complexity | When to Use |
|--------|---------------|---------|------------|-------------|
| **CreateRemoteThread** | ✅ Excellent | ⚠️ Low | ⭐ Simple | Default choice, maximum compatibility |
| **QueueUserAPC** | ⚠️ Moderate | ✅ Good | ⭐⭐ Moderate | Target has alertable threads |
| **NtCreateThreadEx** | ✅ Good | ✅ Good | ⭐⭐ Moderate | Bypass user-mode hooks |
| **Manual Map** | ⚠️ Limited | ✅✅ Excellent | ⭐⭐⭐ Complex | Stealth injection, bypass module list |

### 1. CreateRemoteThread

**Overview:**
- Classic injection technique
- Creates a remote thread in the target process
- Calls LoadLibraryA to load the DLL

**Pros:**
- Works on all Windows versions (XP to 11)
- Most reliable and predictable
- Well-documented and understood
- Best for learning and testing

**Cons:**
- Well-known to anti-cheat and security software
- Easily detected by monitoring CreateRemoteThread API
- Shows up in module list (PEB)

**Best for:**
- Educational purposes
- Testing your own applications
- Maximum compatibility needed
- Quick and simple injection

### 2. QueueUserAPC

**Overview:**
- Injects via Asynchronous Procedure Call (APC)
- Queues LoadLibraryA call to alertable thread
- Executes when thread enters alertable state

**Pros:**
- Stealthier than CreateRemoteThread
- No suspicious remote thread creation
- Good for GUI applications (usually have alertable threads)

**Cons:**
- Requires target to have alertable thread
- May fail on console applications
- Timing-dependent (waits for alertable state)

**Best for:**
- GUI applications (Notepad, Paint, etc.)
- When CreateRemoteThread is detected
- Applications with message loops

**Warning:** May hang if target has no alertable threads!

### 3. NtCreateThreadEx

**Overview:**
- Uses undocumented native API (ntdll.dll)
- Similar to CreateRemoteThread but lower-level
- Bypasses some user-mode hooks

**Pros:**
- More reliable than CreateRemoteThread
- Can bypass certain user-mode hooks
- Often works when CreateRemoteThread fails

**Cons:**
- Uses undocumented API (may change in future Windows)
- Still shows up in module list
- Not truly stealthy

**Best for:**
- When CreateRemoteThread is hooked
- Need more reliability
- Don't need ultimate stealth

### 4. Manual Map

**Overview:**
- Advanced technique that manually maps DLL into memory
- Doesn't use LoadLibrary (bypasses PEB module list)
- Manually resolves imports and relocations

**Pros:**
- Doesn't show in module list (stealthiest)
- Bypasses LoadLibrary hooks
- Most resistant to detection

**Cons:**
- Most complex implementation
- May not work with all DLLs:
  - No Thread Local Storage (TLS) support
  - No delay-loaded imports support
  - DllMain must handle manual mapping correctly
- Harder to debug

**Best for:**
- Maximum stealth required
- Simple DLLs without TLS/delay-load
- Security research
- When all other methods fail

**⚠️ Important:** The test DLL (`test_dll.dll`) works with Manual Map. Your custom DLL must be compatible!

---

## Common Workflows

### Testing a New DLL

**Scenario:** You've written a custom DLL and want to test it.

**Steps:**

1. **Build your DLL**
   ```bash
   cargo build --release
   # or
   cl.exe /LD mydll.cpp /Fe:mydll.dll
   ```

2. **Start a safe test process**
   - Use Notepad, Calculator, or Paint
   - **Never test on system processes!**

3. **Launch injector as admin**
   - Right-click → Run as administrator

4. **Select test process**
   - Search for process name
   - Click to select

5. **Choose your DLL**
   - Click Browse
   - Select your built DLL
   - Ensure path is absolute (not relative!)

6. **Start with CreateRemoteThread**
   - Safest and most compatible method
   - Try other methods if this fails

7. **Check results**
   - Look for MessageBox or other DLL behavior
   - Review log panel for errors
   - Check DLL's log file if it creates one

8. **Debug if needed**
   - See [Troubleshooting](#troubleshooting) section
   - Attach debugger to target process
   - Check Windows Event Viewer for crashes

### Debugging Injection Failures

**Scenario:** Injection fails with an error.

**Common errors and solutions:**

| Error | Cause | Solution |
|-------|-------|----------|
| "Access denied" | Not admin / Insufficient privileges | Run as administrator |
| "Architecture mismatch" | 32-bit injector, 64-bit target (or vice versa) | Use matching architecture |
| "DLL not found" | Path is wrong or relative | Use absolute path |
| "Process not found" | Target closed or wrong name | Start target, verify name |
| "Failed to allocate memory" | Target process restrictions | Try different process or method |
| "LoadLibrary failed" | DLL dependencies missing | Check DLL dependencies with `dumpbin /dependents` |

**Systematic debugging:**

1. **Check basic requirements**
   - [ ] Running as administrator?
   - [ ] SeDebugPrivilege enabled? (shown in UI)
   - [ ] Target process still running?
   - [ ] DLL file exists at specified path?

2. **Verify architecture compatibility**
   - Check if DLL is 32-bit or 64-bit
   - Match injector architecture to target
   - Use `dumpbin /headers mydll.dll` to check

3. **Test with known-good DLL**
   - Use `test_dll.dll` included with injector
   - If test DLL works, issue is with your DLL

4. **Try different injection method**
   - CreateRemoteThread → Most compatible
   - NtCreateThreadEx → If CreateRemoteThread fails
   - QueueUserAPC → For GUI apps
   - Manual Map → Last resort (requires compatible DLL)

5. **Review detailed logs**
   - Check log panel for specifics
   - Open log file in `%APPDATA%\DLLInjector\logs\`
   - Look for Windows error codes

6. **Check DLL dependencies**
   ```cmd
   dumpbin /dependents mydll.dll
   ```
   - Ensure all dependencies are present
   - Use Dependency Walker for deeper analysis

---

## Troubleshooting

### Application Won't Start

**"Application failed to initialize"**
- Install Microsoft Visual C++ Redistributable
- Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe

**"Windows protected your PC" SmartScreen warning**
- Click "More info"
- Click "Run anyway"
- This is normal for unsigned executables

### No Processes Shown in List

**Empty process list:**
- **Cause:** Not running as administrator
- **Solution:** Right-click → Run as administrator

**"Failed to enumerate processes":**
- **Cause:** Windows security restriction
- **Solution:** Restart application as admin

### Injection Fails

**See the dedicated [Troubleshooting Guide](troubleshooting.md) for comprehensive solutions.**

Quick checks:

1. ✅ Running as admin?
2. ✅ SeDebugPrivilege enabled?
3. ✅ Target process still running?
4. ✅ DLL path is absolute?
5. ✅ Architecture matches (both 64-bit or both 32-bit)?

### Target Process Crashes After Injection

**DllMain issues:**
- Don't do heavy work in DllMain
- Don't call LoadLibrary in DllMain (deadlock risk)
- Keep DllMain minimal and fast

**Dependencies missing:**
- Your DLL depends on other DLLs not present in target
- Use `dumpbin /dependents` to check

**Wrong architecture:**
- 32-bit DLL injected into 64-bit process (or vice versa)
- Verify both are same architecture

**TLS callbacks:**
- Some DLLs use Thread Local Storage callbacks
- Manual Map doesn't support TLS
- Use a different injection method

### Logs Not Saving

**Logs disappear after closing:**
- Logs ARE saved to disk
- Location: `%APPDATA%\DLLInjector\logs\`
- Open File Explorer and paste that path

**Can't find log files:**
1. Press Win+R
2. Type: `%APPDATA%\DLLInjector\logs`
3. Press Enter

---

## Best Practices

### Safe Testing

**✅ DO:**
- Test on simple processes (Notepad, Calculator, Paint)
- Use the included `test_dll.dll` first
- Test in a VM if possible
- Create backups before testing on important applications
- Start with CreateRemoteThread method
- Check logs after every injection

**❌ DON'T:**
- Inject into system processes (csrss.exe, lsass.exe, winlogon.exe)
- Inject into Windows Explorer (explorer.exe) - can crash desktop
- Inject into antivirus processes
- Test on production systems
- Inject into online games (ToS violation, ban risk)

### Architecture Compatibility

**Important rules:**

- **64-bit injector** can only inject into **64-bit processes**
- **32-bit injector** can only inject into **32-bit processes**
- Check task manager: 32-bit processes show "(32 bit)" suffix

**How to tell:**
```bash
# Check your injector
dumpbin /headers injector.exe | findstr machine
# 8664 machine (x64) = 64-bit
# 14C machine (x86) = 32-bit

# Check your DLL
dumpbin /headers mydll.dll | findstr machine
```

**Solution for mixed scenarios:**
- Build both 32-bit and 64-bit versions
- Use 64-bit for most modern applications
- Use 32-bit for legacy applications

### DllMain Best Practices

**Your DLL's DllMain should:**

```cpp
// Good DllMain - minimal and fast
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            // Create thread for your actual work
            CreateThread(NULL, 0, MyThreadProc, NULL, 0, NULL);
            break;
    }
    return TRUE;
}

// Bad DllMain - heavy work, high crash risk!
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // ❌ DON'T: Call LoadLibrary (loader lock deadlock!)
        LoadLibraryA("some_other.dll");

        // ❌ DON'T: Do heavy initialization
        InitializeComplexSystem();

        // ❌ DON'T: Sync with other threads
        WaitForSingleObject(hEvent, INFINITE);
    }
    return TRUE;
}
```

**Key rules:**
1. **Keep DllMain minimal** - Just set flags, create threads
2. **Never call LoadLibrary** - Causes loader lock deadlock
3. **Call DisableThreadLibraryCalls** - Improves performance
4. **Do real work in a thread** - Create thread from DllMain
5. **Don't synchronize** - No mutexes, events, or waits

---

## Advanced Usage

### Command-Line Interface

For automation and scripting, use `injector-cli.exe`:

```bash
# Basic usage
injector-cli.exe <process_name_or_pid> <dll_path> [method]

# Examples
injector-cli.exe notepad.exe C:\path\to\test_dll.dll
injector-cli.exe 1234 C:\path\to\test_dll.dll crt
injector-cli.exe calc.exe C:\path\to\test_dll.dll manual

# Methods: crt, apc, nt, manual
```

See `injector-cli.exe --help` for full documentation.

### Programmatic Usage (Library)

Use `injector-core` as a library in your Rust projects:

```toml
# Cargo.toml
[dependencies]
injector-core = { path = "../injector-core" }
```

```rust
// Your code
use injector_core::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    PrivilegeManager::enable_debug_privilege()?;

    let processes = ProcessEnumerator::find_by_name("notepad")?;
    let target = processes.first().unwrap();

    let handle = ProcessHandle::open(
        target.pid,
        PROCESS_ALL_ACCESS
    )?;

    let injector = CreateRemoteThreadInjector;
    injector.inject(&handle, Path::new(r"C:\test.dll"))?;

    Ok(())
}
```

See [API Reference](api-reference.md) for complete documentation.

### Batch Injection

Inject into multiple processes:

```rust
// Example: Inject into all instances of a process
let processes = ProcessEnumerator::find_by_name("chrome")?;
let dll_path = Path::new(r"C:\my.dll");
let injector = CreateRemoteThreadInjector;

for process in processes {
    let handle = ProcessHandle::open(process.pid, injector.required_access())?;

    match injector.inject(&handle, dll_path) {
        Ok(_) => println!("✅ Injected into PID {}", process.pid),
        Err(e) => eprintln!("❌ Failed PID {}: {}", process.pid, e),
    }
}
```

**⚠️ Warning:** Only do this for processes you own! Never batch-inject into system processes.

### Custom Injection Logic

Implement your own injection method:

```rust
use injector_core::injection::InjectionMethod;

struct MyCustomInjector;

impl InjectionMethod for MyCustomInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        // Your custom injection logic here
        todo!()
    }

    fn name(&self) -> &'static str {
        "My Custom Method"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_ALL_ACCESS
    }
}
```

---

## Getting Help

**Resources:**
- [Architecture Documentation](architecture.md) - Technical details
- [API Reference](api-reference.md) - Library documentation
- [Testing Guide](TESTING.md) - Test strategy
- [Legal Disclaimer](legal-disclaimer.md) - **Read before using!**
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute

**Still stuck?**
- Check GitHub Issues
- Search closed issues for similar problems
- Open a new issue with:
  - Windows version
  - Injector version
  - Target process name
  - Injection method used
  - Full error message
  - Log file contents

---

## Legal Notice

⚠️ **This tool is for educational and authorized testing only.**

**By using this software, you agree to:**
- Only inject into processes you own or have permission to modify
- Never use for cheating in games or bypassing security
- Comply with all applicable laws and Terms of Service
- Accept full responsibility for your actions

**See [Legal Disclaimer](legal-disclaimer.md) for complete terms.**

Misuse can result in:
- Account bans (permanent)
- Legal action (civil/criminal)
- Financial penalties
- Criminal record

**Use responsibly and legally!**

---

**Last Updated:** 2026-02-12
**Version:** 0.1.0

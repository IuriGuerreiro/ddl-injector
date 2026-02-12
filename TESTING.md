# Testing the DLL Injection

This guide shows you how to test the CreateRemoteThread injection method.

## What We've Built

1. **test-dll** - A simple DLL that shows a message box when injected
2. **injector-cli** - A command-line tool to inject DLLs into processes

## Test Files Location

- Test DLL: `target/release/test_dll.dll`
- CLI Tool: `target/release/injector-cli.exe`

## Quick Test (Recommended)

### Step 1: Start a Target Process

Open **Notepad** (notepad.exe) - it's a simple, safe target for testing.

```powershell
notepad
```

### Step 2: Run the Injection (As Administrator)

Open PowerShell **as Administrator** and run:

```powershell
cd F:\Projects\Cheats\dllInjector

# Inject into notepad using process name
.\target\release\injector-cli.exe notepad.exe .\target\release\test_dll.dll
```

### Expected Result

You should see:
1. CLI output showing the injection process
2. **A message box appears in/over Notepad** saying "Test DLL successfully injected!"

If you see the message box, **congratulations! The injection works!** 🎉

## Detailed Test Output

When successful, you'll see output like:

```
🔍 Searching for process: notepad.exe
   Looking for process name: notepad.exe
✓ Found process: notepad.exe (PID 12345)
   Path: C:\Windows\system32\notepad.exe

💉 Using injection method: CreateRemoteThread
   DLL path: F:\Projects\Cheats\dllInjector\target\release\test_dll.dll

🔓 Opening process handle...
✓ Process handle opened successfully

💉 Injecting DLL...

✅ Injection successful!
   The DLL should now be loaded in the target process
```

## Enable Debug Logging

For more detailed output, set the `RUST_LOG` environment variable:

```powershell
$env:RUST_LOG="debug"
.\target\release\injector-cli.exe notepad.exe .\target\release\test_dll.dll
```

This will show:
- Memory allocation addresses
- LoadLibraryW address
- Thread creation details
- Exit codes

## Alternative Test Targets

You can inject into any process, for example:

### Calculator
```powershell
calc
.\target\release\injector-cli.exe Calculator.exe .\target\release\test_dll.dll
```

### Using PID instead of name
```powershell
# Find PID using Task Manager or:
tasklist | findstr notepad

# Inject using PID
.\target\release\injector-cli.exe 12345 .\target\release\test_dll.dll
```

## Common Issues and Solutions

### ❌ "Failed to open process: Access denied"

**Solution:** Run PowerShell as Administrator

```powershell
# Right-click PowerShell → "Run as Administrator"
```

### ❌ "DLL file not found"

**Solution:** Use absolute path or verify the file exists

```powershell
# Use full path
.\target\release\injector-cli.exe notepad.exe "F:\Projects\Cheats\dllInjector\target\release\test_dll.dll"

# Or verify file exists
Test-Path .\target\release\test_dll.dll
```

### ❌ "Architecture mismatch"

**Solution:** Build matching architecture

```powershell
# For 64-bit processes (most modern Windows apps)
cargo build -p test-dll --release

# For 32-bit processes (rare, legacy apps)
cargo build -p test-dll --release --target i686-pc-windows-msvc
```

### ❌ No message box appears

**Possible causes:**
1. Process may have blocked the injection (antivirus/anti-cheat)
2. Wrong architecture (32-bit DLL into 64-bit process or vice versa)
3. DLL crashed during initialization

**Debug steps:**
```powershell
# Enable debug logging
$env:RUST_LOG="debug"
.\target\release\injector-cli.exe notepad.exe .\target\release\test_dll.dll
```

## Programmatic Testing

You can also test programmatically from Rust code:

```rust
use injector_core::*;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Find notepad
    let processes = ProcessEnumerator::find_by_name("notepad.exe")?;
    let target = &processes[0];

    // Create injector
    let injector = CreateRemoteThreadInjector::new();

    // Open handle
    let handle = ProcessHandle::open(target.pid, injector.required_access())?;

    // Inject
    let dll_path = PathBuf::from("F:\\Projects\\Cheats\\dllInjector\\target\\release\\test_dll.dll");
    injector.inject(&handle, &dll_path)?;

    println!("Injection successful!");
    Ok(())
}
```

## Advanced Testing: Custom DLL

Want to test with your own DLL? Create one that does something visible:

### Minimal Test DLL (C++)

```cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "Custom DLL Loaded!", "Test", MB_OK);
    }
    return TRUE;
}
```

Compile with MSVC:
```cmd
cl /LD test.cpp /link /OUT:test.dll
```

## Verify Injection with Process Explorer

1. Download [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
2. Run it as Administrator
3. Find your target process (e.g., notepad.exe)
4. Double-click → DLLs tab
5. Look for `test_dll.dll` in the list

## Safety Notes

⚠️ **Only inject into processes you own or have permission to modify**

- ✅ Safe: notepad.exe, calc.exe, your own test programs
- ❌ Unsafe: System processes, games with anti-cheat, other users' processes

## Next Steps

Once basic injection works:

1. **Test architecture validation** - Try injecting mismatched architectures
2. **Test error handling** - Try invalid paths, non-existent processes
3. **Create custom DLLs** - Make DLLs that hook functions, modify behavior
4. **Move to Phase 4** - Build the GUI for easier testing

## Questions?

If injection isn't working:

1. Check you're running as Administrator
2. Verify the DLL file exists: `Test-Path .\target\release\test_dll.dll`
3. Enable debug logging: `$env:RUST_LOG="debug"`
4. Try a different target process
5. Check Windows Defender / antivirus isn't blocking it

Happy injecting! 🎯

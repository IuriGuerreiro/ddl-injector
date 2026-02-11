# Troubleshooting Guide

Common issues and solutions for the DLL Injector.

## Table of Contents

1. [Build Issues](#build-issues)
2. [Runtime Issues](#runtime-issues)
3. [Injection Failures](#injection-failures)
4. [UI Problems](#ui-problems)
5. [Privilege Issues](#privilege-issues)
6. [Performance Issues](#performance-issues)

## Build Issues

### Linker Not Found

**Error:**
```
error: linker `link.exe` not found
```

**Solution:**
Install Visual Studio Build Tools with "Desktop development with C++" workload.

Download: https://visualstudio.microsoft.com/downloads/

### Windows Crate Compilation Errors

**Error:**
```
error: failed to compile windows-sys
```

**Solutions:**
1. Update Rust: `rustup update`
2. Clean build: `cargo clean && cargo build`
3. Check Rust version: `rustc --version` (need 1.75+)

### Dependency Resolution Failures

**Error:**
```
error: failed to select a version for `package`
```

**Solutions:**
1. Update dependencies: `cargo update`
2. Check Cargo.lock conflicts
3. Delete Cargo.lock and rebuild

## Runtime Issues

### Application Won't Start

**Symptoms:**
- Window doesn't appear
- Immediate crash
- No error message

**Solutions:**
1. **Update graphics drivers**
   - egui requires OpenGL/DirectX support
   - Check GPU manufacturer website

2. **Run from terminal**
   ```bash
   cargo run -p injector-ui
   ```
   View error messages directly

3. **Check Windows Event Viewer**
   - Windows Logs → Application
   - Look for crash reports

4. **Try compatibility mode**
   - Right-click exe → Properties → Compatibility
   - Try "Windows 8" mode

### Configuration File Corruption

**Error:**
```
Failed to load configuration: invalid JSON
```

**Solution:**
Delete config file (will be regenerated):
```bash
del %APPDATA%\dllInjector\config.json
```

### Log File Permission Denied

**Error:**
```
Failed to create log file: Access denied
```

**Solutions:**
1. Run as administrator
2. Check antivirus isn't blocking
3. Manually create log directory:
   ```bash
   mkdir %APPDATA%\dllInjector\logs
   ```

## Injection Failures

### Access Denied (Error 5)

**Error:**
```
Failed to open process: Access denied (OS Error 5)
```

**Causes:**
1. Insufficient privileges
2. Protected process
3. Anti-cheat protection

**Solutions:**

1. **Run as Administrator**
   - Right-click exe → "Run as administrator"

2. **Enable SeDebugPrivilege**
   - Application attempts this automatically
   - Requires administrator rights

3. **Target is protected**
   - Some processes can't be injected (anti-malware, system)
   - Games with kernel-level anti-cheat (BattleEye, EAC)
   - Try different injection method (manual mapping may work)

### Architecture Mismatch

**Error:**
```
Architecture mismatch: injector is x64, target is x86
```

**Solutions:**
- Can't inject 64-bit DLL into 32-bit process
- Can't inject 32-bit DLL into 64-bit process
- Build matching architecture DLL
- Check target process architecture first

### DLL Not Found

**Error:**
```
DLL file not found: C:\path\to\dll.dll
```

**Solutions:**
1. **Use absolute paths**
   - Don't use relative paths
   - Use file picker to ensure correct path

2. **Check file exists**
   ```bash
   dir "C:\path\to\dll.dll"
   ```

3. **Check permissions**
   - Ensure DLL is readable
   - Not locked by another process

### DLL Path Too Long

**Error:**
```
Failed to write DLL path: buffer too small
```

**Solution:**
Windows has MAX_PATH limit (260 characters). Move DLL to shorter path:
```
C:\dll.dll  # Good
C:\very\long\path\that\exceeds\windows\maximum\path\length\limit\dll.dll  # Bad
```

### LoadLibrary Failed

**Error:**
```
Remote thread returned error code
```

**Causes:**
1. DLL has missing dependencies
2. DLL is corrupted
3. DLL requires different architecture
4. DLL initialization failed (DllMain returned FALSE)

**Solutions:**

1. **Check DLL dependencies**
   ```bash
   dumpbin /dependents your.dll
   ```
   Ensure all dependencies are in target process or PATH

2. **Test DLL locally**
   ```rust
   // Test if DLL loads in current process
   let handle = unsafe { LoadLibraryA(s!("C:\\path\\to\\dll.dll")) };
   ```

3. **Check DllMain**
   - Ensure DllMain returns TRUE
   - Check for crashes in DllMain
   - Add logging to DllMain

### Manual Mapping Fails

**Specific to Manual Mapping method**

**Import Resolution Failed:**
- Check all imported DLLs exist in target
- Verify function names are correct
- Some functions may not exist in target process

**Relocation Failed:**
- PE file may have corrupted relocation section
- Try different base address
- Some DLLs can't be relocated

**Section Protection Failed:**
- VirtualProtectEx may fail
- Check DEP (Data Execution Prevention) settings
- Try different sections

## UI Problems

### Window Too Small

**Solution:**
Resize window or delete config to reset:
```bash
del %APPDATA%\dllInjector\config.json
```

### Process List Empty

**Causes:**
1. Insufficient privileges to enumerate
2. Windows API call failed

**Solutions:**
1. Run as administrator
2. Check logs for error message
3. Restart application

### Log Viewer Not Updating

**Solutions:**
1. Check log level filter
2. Clear logs and retry
3. Restart application

### UI Freezes During Injection

**Cause:**
Synchronous injection blocks UI thread

**Workaround:**
Wait for injection to complete (typically < 1 second)

**Future Fix:**
Phase 11 will add async injection

## Privilege Issues

### SeDebugPrivilege Not Enabled

**Error:**
```
Failed to adjust token privileges
```

**Solutions:**

1. **Run as Administrator**
   - Required to enable SeDebugPrivilege

2. **Check User Account**
   - Must be in Administrators group
   - Standard users cannot enable debug privilege

3. **Group Policy**
   - May be disabled by domain policy
   - Check: `secpol.msc` → Local Policies → User Rights Assignment → Debug programs

### UAC Prompts Every Time

**Cause:**
Application requests administrator privileges

**Solutions:**

1. **Accept UAC prompt**
   - Required for SeDebugPrivilege

2. **Disable UAC** (not recommended)
   - Control Panel → User Accounts → Change UAC settings
   - Security risk

3. **Create scheduled task**
   - Run with highest privileges without prompt
   - Task Scheduler → Create Task → Run with highest privileges

## Performance Issues

### Slow Process Enumeration

**Cause:**
Enumerating thousands of processes takes time

**Solutions:**
1. Use search/filter
2. Refresh only when needed
3. Close unnecessary processes

### High Memory Usage

**Cause:**
Large log buffer

**Solutions:**
1. Clear logs periodically
2. Adjust log level to WARN or ERROR
3. Restart application

### Slow Injection

**Typical times:**
- CreateRemoteThread: 10-100ms
- Manual Mapping: 100-500ms
- QueueUserAPC: Variable (depends on thread alerting)
- NtCreateThreadEx: 10-100ms

**If slower:**
1. Check antivirus isn't scanning
2. Close unnecessary programs
3. Check target process isn't frozen

## Error Codes

### Common Windows Error Codes

| Code | Name | Meaning | Solution |
|------|------|---------|----------|
| 5 | ERROR_ACCESS_DENIED | Insufficient privileges | Run as admin |
| 87 | ERROR_INVALID_PARAMETER | Invalid API parameter | Check paths/parameters |
| 299 | ERROR_PARTIAL_COPY | Can't read/write process memory | Target may be protected |
| 998 | ERROR_NOACCESS | Invalid memory access | Check addresses are valid |

### Viewing Error Codes

Windows errors shown as:
```
Failed to open process (OS Error 5)
```

The number is the Windows error code.

## Anti-Cheat Conflicts

### BattleEye / EasyAntiCheat

**Problem:**
Kernel-level anti-cheat blocks all injection

**Solutions:**
- None (by design)
- These anti-cheats specifically prevent injection
- Don't attempt to bypass (violates TOS and may be illegal)

### Game-Specific Protection

**Problem:**
Some games have custom protection

**Solutions:**
1. Try different injection method
2. Manual mapping is stealthier
3. Check game forums for compatibility

**Warning:**
Injecting into online games may result in:
- Account bans
- Legal consequences
- Violating terms of service

Only inject into:
- Single-player games (with permission)
- Your own applications
- Authorized testing environments

## Logging for Debugging

### Enable Verbose Logging

```bash
$env:RUST_LOG="trace"
cargo run -p injector-ui
```

### Check Log Files

Logs saved to:
```
%APPDATA%\dllInjector\logs\
```

### Useful Log Messages

Look for:
- "Failed to..." - Error messages
- "Attempting injection..." - Injection start
- "Injection successful" - Success confirmation
- Stack traces for crashes

## Getting More Help

### Before Asking for Help

Collect this information:
1. Windows version: `winver`
2. Rust version: `rustc --version`
3. Error message (full text)
4. Log files
5. Steps to reproduce

### Where to Get Help

1. **Documentation**
   - Check [Architecture](architecture.md)
   - Read relevant [Phase Guide](phases/)

2. **GitHub Issues**
   - Search existing issues
   - Create new issue with template

3. **Community**
   - GitHub Discussions
   - Include collected information

### Reporting Bugs

Include:
- Operating System
- Application version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Log files
- Screenshots (if UI issue)

## Known Issues

### Windows 11 22H2 VirtualProtectEx Issue

**Problem:**
Some Windows 11 versions have VirtualProtectEx bugs

**Workaround:**
- Update Windows to latest version
- Or use different injection method

### egui Scaling on High-DPI

**Problem:**
UI may be too large/small on high-DPI displays

**Solution:**
- Windows will handle DPI scaling
- Or adjust display scaling in Windows settings

## Prevention Tips

### Avoiding Common Issues

1. **Always use absolute paths**
   - Not "dll.dll" but "C:\full\path\to\dll.dll"

2. **Run as administrator**
   - Most injection requires elevated privileges

3. **Check architecture**
   - Match DLL architecture to target process

4. **Test DLL first**
   - Load DLL in test program before injection

5. **Read error messages**
   - Error messages contain useful information

6. **Check logs**
   - Enable debug logging for troubleshooting

7. **Keep software updated**
   - Update Windows
   - Update graphics drivers
   - Update Rust toolchain

## Advanced Debugging

### Using WinDbg

1. Attach WinDbg to injector process
2. Set breakpoint on CreateRemoteThread
3. Step through injection process
4. Examine target process memory

### Using Process Monitor

1. Run Process Monitor (procmon.exe)
2. Filter by process name
3. Observe registry/file/network access
4. Look for access denied errors

### Using Process Hacker

1. Open Process Hacker
2. View process properties
3. Check modules loaded
4. Examine memory regions
5. View handles

## Last Resort

If nothing works:

1. **Clean reinstall**
   ```bash
   cargo clean
   rm -rf target
   cargo build --release
   ```

2. **Reset configuration**
   ```bash
   rm -rf %APPDATA%\dllInjector
   ```

3. **Check Windows integrity**
   ```bash
   sfc /scannow
   ```

4. **Ask for help**
   - Provide all collected information
   - Include logs and error messages
   - Describe exactly what you tried

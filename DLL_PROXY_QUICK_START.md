# DLL Proxy Quick Start Guide

## What is DLL Proxy/Hijacking?

DLL proxying replaces a legitimate system DLL (like `version.dll`) that your target application loads. Your proxy DLL forwards all functions to the real system DLL while executing your payload in the background.

**Key Benefit**: Loads before anti-cheat systems initialize, bypassing runtime injection detection entirely.

## Requirements

1. Rust toolchain installed (`cargo` in PATH)
2. Target application must be closed
3. Write permissions to target application directory

Check Rust installation:
```bash
cargo --version
```

If not installed: https://rustup.rs/

## Basic Usage

### Step 1: Identify Target DLL

Use Process Monitor or Process Hacker to see which DLLs your application loads.

**Recommended starter DLLs:**
- `version.dll` - Most commonly loaded, simplest to proxy (17 exports)
- `winmm.dll` - Multimedia applications (181 exports)
- `xinput1_3.dll` - Games with controller support (15 exports)

### Step 2: Prepare Your Payload

Your payload DLL should have a `DllMain` that executes when loaded:

```rust
#[no_mangle]
extern "system" fn DllMain(
    _hinst_dll: *const u8,
    fdw_reason: u32,
    _lpv_reserved: *const u8,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if fdw_reason == DLL_PROCESS_ATTACH {
        // Your code here
        std::thread::spawn(|| {
            // Do your work in a separate thread
            std::fs::write("C:\\test\\loaded.txt", "Payload executed!").ok();
        });
    }

    1 // Return TRUE
}
```

### Step 3: Generate and Deploy Proxy

```bash
injector-cli --method dll-proxy \
    --target-exe "C:\Path\To\YourApp\app.exe" \
    --dll-path "C:\Path\To\Your\payload.dll" \
    --system-dll "version.dll" \
    --backup
```

**What happens:**
1. Parses exports from `C:\Windows\System32\version.dll`
2. Generates Rust proxy source code
3. Compiles proxy with `cargo build --release` (~10-30 seconds)
4. Backs up existing `version.dll` in app directory (if present)
5. Deploys proxy to `C:\Path\To\YourApp\version.dll`

### Step 4: Test

Launch your application normally:
```bash
C:\Path\To\YourApp\app.exe
```

The proxy loads automatically:
- Application continues to work normally
- Your payload executes in the background

### Step 5: Cleanup

Restore original DLL:
```bash
injector-cli --method dll-proxy \
    --target-exe "C:\Path\To\YourApp\app.exe" \
    --cleanup
```

## Example: Testing Anti-Cheat with version.dll

```bash
# 1. Close your test application
taskkill /F /IM testapp.exe

# 2. Deploy proxy
injector-cli --method dll-proxy \
    --target-exe "C:\TestApp\testapp.exe" \
    --dll-path "C:\payloads\test_payload.dll" \
    --system-dll "version.dll" \
    --backup

# 3. Launch application
C:\TestApp\testapp.exe

# 4. Check if your anti-cheat detected it

# 5. Cleanup when done
injector-cli --method dll-proxy \
    --target-exe "C:\TestApp\testapp.exe" \
    --cleanup
```

## Command Line Arguments

### Required for Deployment
- `--method dll-proxy` - Use DLL proxy method
- `--target-exe <PATH>` - Path to target executable
- `--dll-path <PATH>` - Path to your payload DLL
- `--system-dll <NAME>` - System DLL name to proxy

### Optional
- `--backup` - Backup original DLL (recommended, enabled by default)
- `--cleanup` - Restore from backup instead of deploying

### Not Used for DLL Proxy
- `PROCESS` - Not needed (no runtime injection)
- `DLL_PATH` (positional) - Use `--dll-path` instead

## Troubleshooting

### "cargo not found in PATH"

Install Rust toolchain:
```bash
# Download and run: https://rustup.rs/
```

### "Target directory not found"

Ensure target executable path is correct and exists:
```bash
# Check if file exists
dir "C:\Path\To\YourApp\app.exe"
```

### "Proxy compilation failed"

Check cargo output for errors. Common issues:
- Corrupted system DLL (try another DLL)
- Disk space issues
- Antivirus blocking compilation

### "Access denied" when deploying

Run as Administrator:
```bash
# Right-click Command Prompt -> Run as Administrator
```

### Application crashes on launch

This usually means export forwarding failed. Try:
1. Different target DLL (start with `version.dll`)
2. Check if application has custom DLL loader
3. Verify payload DLL is valid

### Antivirus detects proxy as malware

This is expected behavior:
1. The proxy contains embedded DLL bytes
2. It loads code from temp directory
3. Add exception in your AV for testing

## CLI Help

View all options:
```bash
injector-cli --help
```

View DLL proxy specific info:
```bash
injector-cli --method dll-proxy --help
```

## Verification

Check if proxy was deployed:
```bash
dir "C:\Path\To\YourApp\version.dll"
dir "C:\Path\To\YourApp\version.dll.backup"
```

Verify proxy is different from system DLL:
```bash
fc /b "C:\Windows\System32\version.dll" "C:\Path\To\YourApp\version.dll"
```

Should show differences (they're different files).

## Best Practices

### For Testing Anti-Cheat

1. **Test Detection**: Verify your anti-cheat detects the proxy DLL
2. **Test Timing**: Confirm anti-cheat loads before the proxy
3. **Test Signatures**: Check if signature validation catches modified DLLs
4. **Test Integrity**: Verify file hash checks work correctly

### For Development

1. **Always Use --backup**: Protect original files
2. **Test with Simple DLLs First**: Start with `version.dll`
3. **Close Application Before Deploy**: Prevent file locking
4. **Use Process Monitor**: Verify DLL load order
5. **Keep Logs**: Enable logging with `RUST_LOG=debug`

## Common System DLLs for Testing

Sorted by ease of use:

| DLL | Exports | Difficulty | Notes |
|-----|---------|------------|-------|
| version.dll | 17 | ⭐ Easy | Best for beginners |
| xinput1_3.dll | 15 | ⭐ Easy | Only if app uses controller |
| dsound.dll | 67 | ⭐⭐ Medium | DirectSound games |
| winmm.dll | 181 | ⭐⭐⭐ Hard | Many exports |
| d3d9.dll | 150+ | ⭐⭐⭐ Hard | DirectX 9 games |

## Performance Notes

- **Generation Time**: 5-30 seconds (compiling Rust code)
- **First Run**: Slower (downloads crates, ~1-2 minutes)
- **Subsequent Runs**: Faster (cached dependencies)
- **Proxy Overhead**: Negligible (forwarding is fast)

## Security Warning

This tool is for **testing your own anti-cheat systems**. Do not use it to:
- Bypass anti-cheat in online games you don't own
- Cheat in multiplayer games
- Violate terms of service of applications

Unauthorized use may violate:
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

## Need Help?

Check the detailed implementation guide:
```bash
# View full documentation
notepad DLL_PROXY_IMPLEMENTATION.md
```

View source code:
```bash
# Core implementation
explorer injector-core\src\injection\dll_proxy.rs
explorer injector-core\src\injection\proxy_generator.rs
explorer injector-core\src\pe\exports.rs
```

## Next Steps

1. Read `DLL_PROXY_IMPLEMENTATION.md` for technical details
2. Check example payloads in `examples/` directory
3. Implement detection in your anti-cheat
4. Test with different target DLLs
5. Monitor with Process Monitor to verify load order

---

**Remember**: This is a powerful technique. Use it responsibly for security research and testing your own systems only.

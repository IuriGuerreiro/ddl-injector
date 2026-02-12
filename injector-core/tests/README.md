# Testing Documentation

This document provides comprehensive guidance for running and understanding the DLL Injector test suite.

## Test Organization

The test suite is organized into three categories:

### 1. Unit Tests (`cargo test --lib`)
Fast, isolated tests that don't require admin privileges. These tests verify individual components:

- **PE Parser Tests** (~45 tests): DOS/NT header validation, section mapping, import resolution, relocations, TLS, exceptions
- **Memory Module Tests** (~20 tests): Remote memory allocation, read/write operations, RAII semantics
- **Process & Error Tests** (~21 tests): Thread enumeration, error type conversions, error messages
- **Injection Method Tests** (~24 tests): Method validation, required access flags, function lookups

**Total Unit Tests:** ~110 tests

### 2. Integration Tests - Non-Admin (`cargo test --test integration_test`)
Tests that can run without administrator privileges:

- **Process Enumeration Tests**: Verify process listing and searching
- **PE Parser Integration Tests**: Test PE parsing with real DLL files
- **Architecture Validation Tests**: Check architecture compatibility detection

**Total Non-Admin Integration Tests:** 4 tests

### 3. Integration Tests - Admin Required (`cargo test --test integration_test -- --ignored`)
End-to-end tests that require administrator privileges:

- **Injection Method Tests**: Test all 4 injection methods with real process injection
  - CreateRemoteThread
  - Manual Map
  - QueueUserAPC
  - NtCreateThreadEx
- **Error Handling Tests**: Missing DLL, architecture mismatch
- **Privilege Tests**: Administrator detection, debug privilege enable

**Total Admin Integration Tests:** 8 tests

---

## Running Tests

### Quick Start - All Unit Tests
```bash
cargo test -p injector-core
```

### Run Only PE Parser Tests
```bash
cargo test -p injector-core pe:: --lib
```

### Run Only Memory Tests
```bash
cargo test -p injector-core memory:: --lib
```

### Run Non-Admin Integration Tests
```bash
cargo test --test integration_test
```

### Run Admin Integration Tests (Requires Admin)
**Important:** Open PowerShell/CMD as Administrator first!

```bash
cargo test --test integration_test -- --ignored --test-threads=1
```

**Note:** Use `--test-threads=1` to run integration tests sequentially, preventing interference between tests.

---

## Test Fixtures

### Test DLL
The integration tests use a test DLL located at `target/release/test_dll.dll`.

**Build the test DLL:**
```bash
cargo build -p test-dll --release --features silent
```

**Features:**
- `silent`: Disables MessageBox popups for automated testing
- Creates marker file at `%TEMP%\dll_injector_test_marker.txt` when loaded
- Exports `test_exported_function()` that returns 42
- Tracks load count via atomic counter

### Marker File Mechanism
The test DLL creates a marker file to verify successful injection:

**Location:** `%TEMP%\dll_injector_test_marker.txt`

**Contents:**
```
DLL Injected Successfully
Timestamp: 1234567890
Load Count: 1
Process ID: 5678
```

Integration tests use this marker file to verify that:
1. The DLL was successfully injected
2. The DLL executed (DllMain was called)
3. The injection occurred in the correct process

---

## Coverage Measurement

### Install Tarpaulin (Linux/WSL only)
```bash
cargo install cargo-tarpaulin
```

### Generate Coverage Report
```bash
cargo tarpaulin --out Html --output-dir coverage
```

**Current Coverage:** ~70% line coverage

---

## Troubleshooting

### Issue: "Test DLL not found"
**Solution:** Build the test DLL first:
```bash
cargo build -p test-dll --release --features silent
```

### Issue: "Failed to open process - run as administrator"
**Solution:** The integration test requires admin privileges. Run your terminal as Administrator:
```bash
# Right-click PowerShell/CMD -> "Run as Administrator"
cargo test --test integration_test -- --ignored
```

### Issue: "Marker file not created - DLL did not execute"
**Possible Causes:**
1. Antivirus blocked the injection
2. DEP (Data Execution Prevention) prevented execution
3. Test DLL not built with `--features silent`
4. Injection method failed silently

**Debug Steps:**
1. Check Windows Event Viewer for application crashes
2. Temporarily disable antivirus
3. Rebuild test DLL: `cargo build -p test-dll --release --features silent`
4. Run with `RUST_LOG=debug` for detailed logging:
   ```bash
   $env:RUST_LOG="debug"
   cargo test --test integration_test -- --ignored --nocapture
   ```

### Issue: Integration tests hang
**Solution:** Use `--test-threads=1` to run tests sequentially:
```bash
cargo test --test integration_test -- --ignored --test-threads=1
```

### Issue: "QueueUserAPC injection failed"
**Note:** QueueUserAPC requires alertable threads. Some processes may not have alertable threads immediately after startup. This is expected behavior - the test verifies that the APC was queued successfully, but execution depends on thread state.

### Issue: Tests fail on 32-bit Windows
**Solution:** The test suite is designed for 64-bit Windows. Architecture validation tests will fail on 32-bit systems. This is expected.

---

## Test Development Guidelines

### Adding New Unit Tests
1. Add test module to the appropriate file:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_new_functionality() {
           // Test implementation
       }
   }
   ```

2. Run tests to verify:
   ```bash
   cargo test -p injector-core --lib
   ```

### Adding New Integration Tests
1. Add test to `tests/integration_test.rs`
2. If test requires admin: Add `#[ignore]` attribute
3. Use helper functions from `mod helpers`
4. Clean up spawned processes: `let _ = child.kill();`

### Best Practices
- **Isolation**: Each test should be independent
- **Cleanup**: Always clean up resources (processes, files)
- **Timing**: Use `std::thread::sleep` for asynchronous operations
- **Error Messages**: Use descriptive assertion messages
- **Documentation**: Add comments explaining non-obvious test logic

---

## CI/CD Integration

### GitHub Actions
See `.github/workflows/test.yml` for automated CI configuration.

**CI runs:**
- All unit tests (non-admin)
- Non-admin integration tests
- Builds test fixtures

**CI does NOT run:**
- Admin-required integration tests (can't elevate privileges in CI)

**Manual Admin Testing:** Required before releases

---

## Test Statistics

| Category | Count | Admin Required | Duration |
|----------|-------|----------------|----------|
| Unit Tests | ~110 | No | < 1 second |
| Integration (Non-Admin) | 4 | No | < 5 seconds |
| Integration (Admin) | 8 | Yes | ~10 seconds |
| **Total** | **~122** | **Mixed** | **~15 seconds** |

---

## Examples

### Run All Tests (Non-Admin)
```bash
# Run all unit tests
cargo test -p injector-core

# Run all integration tests (non-admin)
cargo test --test integration_test
```

### Run All Tests (Admin)
```bash
# Open PowerShell as Administrator
# Run all unit tests
cargo test -p injector-core

# Run all integration tests (including admin)
cargo test --test integration_test -- --ignored --test-threads=1
```

### Run Specific Test
```bash
# Run specific integration test
cargo test --test integration_test test_manual_map_injection -- --ignored --nocapture
```

### Debug Mode with Logging
```bash
$env:RUST_LOG="debug"
cargo test --test integration_test test_create_remote_thread_injection -- --ignored --nocapture
```

---

## Support

For issues or questions:
1. Check this README
2. Review test output with `--nocapture` flag
3. Enable debug logging with `RUST_LOG=debug`
4. Check Windows Event Viewer for crashes
5. Review [Phase 10 Implementation Plan](../../docs/phase10.md)

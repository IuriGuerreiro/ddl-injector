//! Integration tests for DLL injection.
//!
//! Note: These tests require a test DLL and target process.

use injector_core::*;
use std::path::PathBuf;

#[test]
#[ignore] // Ignore by default - requires setup
fn test_inject_into_notepad() {
    // This test requires:
    // 1. Notepad.exe running
    // 2. Test DLL compiled (tests/fixtures/test.dll)
    // 3. Administrator privileges

    let processes = ProcessEnumerator::find_by_name("notepad.exe")
        .expect("Failed to enumerate processes");

    if processes.is_empty() {
        eprintln!("Notepad not running - skipping test");
        return;
    }

    let process = &processes[0];
    let injector = CreateRemoteThreadInjector::new();

    let handle = ProcessHandle::open(
        process.pid,
        injector.required_access(),
    ).expect("Failed to open process");

    let dll_path = PathBuf::from("F:\\Projects\\Cheats\\dllInjector\\tests\\fixtures\\test.dll");

    let result = injector.inject(&handle, &dll_path);
    assert!(result.is_ok(), "Injection failed: {:?}", result.err());
}

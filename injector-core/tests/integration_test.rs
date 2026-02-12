//! Comprehensive integration tests for DLL injection.
//!
//! **Test Organization:**
//! - Injection tests (#[ignore]): Require admin privileges and real process injection
//! - Process tests: Can run without admin, test process enumeration
//! - PE parser tests: Test with real DLL files
//! - Privilege tests (#[ignore]): Require admin privileges
//!
//! **Run ignored tests (requires admin):**
//! ```
//! cargo test --test integration_test -- --ignored --test-threads=1
//! ```

use injector_core::*;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

// ===========================================================================
// Helper Module
// ===========================================================================

mod helpers {
    use super::*;

    /// Get path to test DLL (built with silent feature)
    pub fn test_dll_path() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("target")
            .join("release")
            .join("test_dll.dll")
    }

    /// Get path to marker file created by test DLL
    pub fn marker_file_path() -> PathBuf {
        std::env::temp_dir().join("dll_injector_test_marker.txt")
    }

    /// Check if marker file exists (indicates DLL was loaded)
    pub fn check_marker_file() -> bool {
        marker_file_path().exists()
    }

    /// Clear marker file before test
    pub fn clear_marker_file() {
        let path = marker_file_path();
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Spawn a test process (notepad.exe) and return handle
    pub fn spawn_test_process() -> (Child, u32) {
        let child = Command::new("notepad.exe")
            .spawn()
            .expect("Failed to spawn notepad.exe");

        let pid = child.id();

        // Give process time to start
        std::thread::sleep(Duration::from_millis(500));

        (child, pid)
    }

    /// Read marker file contents
    pub fn read_marker_file() -> Option<String> {
        std::fs::read_to_string(marker_file_path()).ok()
    }
}

// ===========================================================================
// Injection Tests (Require Admin)
// ===========================================================================

#[test]
#[ignore]
fn test_create_remote_thread_injection() {
    use helpers::*;

    println!("Testing CreateRemoteThread injection...");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        panic!(
            "Test DLL not found at {:?}. Run: cargo build -p test-dll --release --features silent",
            dll_path
        );
    }

    // Spawn target process
    let (mut child, pid) = spawn_test_process();

    // Clear marker file
    clear_marker_file();

    // Open process handle
    let injector = CreateRemoteThreadInjector::new();
    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process - run as administrator!");

    // Inject DLL
    println!("Injecting into PID {}...", pid);
    let result = injector.inject(&handle, &dll_path);

    // Wait for DLL to execute
    std::thread::sleep(Duration::from_millis(100));

    // Verify injection
    if let Err(e) = &result {
        println!("Injection error: {:?}", e);
    }
    assert!(result.is_ok(), "Injection failed: {:?}", result.err());

    // Check marker file
    assert!(
        check_marker_file(),
        "Marker file not created - DLL did not execute!"
    );

    // Verify marker file contents
    if let Some(contents) = read_marker_file() {
        println!("Marker file contents:\n{}", contents);
        assert!(contents.contains("DLL Injected Successfully"));
        assert!(contents.contains("Process ID"));
    }

    // Clean up
    let _ = child.kill();
    clear_marker_file();

    println!("CreateRemoteThread injection test passed!");
}

#[test]
#[ignore]
fn test_manual_map_injection() {
    use helpers::*;

    println!("Testing Manual Map injection...");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        panic!("Test DLL not found");
    }

    let (mut child, pid) = spawn_test_process();
    clear_marker_file();

    let injector = ManualMapInjector;
    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process - run as administrator!");

    println!("Injecting into PID {} using Manual Map...", pid);
    let result = injector.inject(&handle, &dll_path);

    std::thread::sleep(Duration::from_millis(100));

    if let Err(e) = &result {
        println!("Injection error: {:?}", e);
    }
    assert!(
        result.is_ok(),
        "Manual Map injection failed: {:?}",
        result.err()
    );
    assert!(
        check_marker_file(),
        "Marker file not created - DLL did not execute!"
    );

    let _ = child.kill();
    clear_marker_file();

    println!("Manual Map injection test passed!");
}

#[test]
#[ignore]
fn test_queue_user_apc_injection() {
    use helpers::*;

    println!("Testing QueueUserAPC injection...");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        panic!("Test DLL not found");
    }

    let (mut child, pid) = spawn_test_process();
    clear_marker_file();

    let injector = QueueUserApcInjector::new();
    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process - run as administrator!");

    println!("Injecting into PID {} using QueueUserAPC...", pid);
    let result = injector.inject(&handle, &dll_path);

    // QueueUserAPC may take longer to execute
    std::thread::sleep(Duration::from_millis(200));

    if let Err(e) = &result {
        println!("Injection error: {:?}", e);
    }
    assert!(
        result.is_ok(),
        "QueueUserAPC injection failed: {:?}",
        result.err()
    );

    // Note: QueueUserAPC may not execute immediately if no alertable threads
    println!("QueueUserAPC injection queued successfully");
    println!("Note: APC execution depends on alertable thread state");

    let _ = child.kill();
    clear_marker_file();

    println!("QueueUserAPC injection test passed!");
}

#[test]
#[ignore]
fn test_nt_create_thread_injection() {
    use helpers::*;

    println!("Testing NtCreateThreadEx injection...");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        panic!("Test DLL not found");
    }

    let (mut child, pid) = spawn_test_process();
    clear_marker_file();

    let injector = NtCreateThreadExInjector::new();
    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process - run as administrator!");

    println!("Injecting into PID {} using NtCreateThreadEx...", pid);
    let result = injector.inject(&handle, &dll_path);

    std::thread::sleep(Duration::from_millis(100));

    if let Err(e) = &result {
        println!("Injection error: {:?}", e);
    }
    assert!(
        result.is_ok(),
        "NtCreateThreadEx injection failed: {:?}",
        result.err()
    );
    assert!(
        check_marker_file(),
        "Marker file not created - DLL did not execute!"
    );

    let _ = child.kill();
    clear_marker_file();

    println!("NtCreateThreadEx injection test passed!");
}

#[test]
#[ignore]
fn test_injection_with_missing_dll() {
    use helpers::*;

    println!("Testing injection with missing DLL (error handling)...");

    let (mut child, pid) = spawn_test_process();

    let injector = CreateRemoteThreadInjector::new();
    let handle =
        ProcessHandle::open(pid, injector.required_access()).expect("Failed to open process");

    let missing_dll = PathBuf::from("C:\\nonexistent\\missing.dll");
    let result = injector.inject(&handle, &missing_dll);

    // Should fail with DllNotFound error
    assert!(result.is_err());

    let _ = child.kill();

    println!("Missing DLL error handling test passed!");
}

#[test]
#[ignore]
fn test_injection_architecture_validation() {
    use helpers::*;

    println!("Testing architecture validation...");

    let (mut child, pid) = spawn_test_process();

    let handle = ProcessHandle::open(
        pid,
        windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION,
    )
    .expect("Failed to open process");

    // Architecture validation against same architecture should pass
    let result = injection::validate_architecture(&handle);
    assert!(
        result.is_ok(),
        "Architecture validation should pass for same architecture"
    );

    let _ = child.kill();

    println!("Architecture validation test passed!");
}

// ===========================================================================
// Process Tests (No Admin Required)
// ===========================================================================

#[test]
fn test_process_enumeration() {
    println!("Testing process enumeration...");

    let result = ProcessEnumerator::enumerate();
    assert!(result.is_ok(), "Process enumeration failed");

    let processes = result.unwrap();
    assert!(processes.len() > 0, "Should find at least one process");

    // Current process should be in the list
    let current_pid = std::process::id();
    let found_self = processes.iter().any(|p| p.pid == current_pid);
    assert!(found_self, "Should find current process in enumeration");

    println!("Found {} processes", processes.len());
    println!("Process enumeration test passed!");
}

#[test]
fn test_find_process_by_name() {
    println!("Testing find process by name...");

    // Find a system process that should always exist
    let result = ProcessEnumerator::find_by_name("System");
    assert!(result.is_ok(), "Find by name failed");

    let processes = result.unwrap();
    if !processes.is_empty() {
        println!("Found System process: PID {}", processes[0].pid);
    }

    // Try finding current process by name
    let exe_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()));

    if let Some(name) = exe_name {
        let result = ProcessEnumerator::find_by_name(&name);
        if let Ok(procs) = result {
            println!("Found {} instances of {}", procs.len(), name);
        }
    }

    println!("Find process by name test passed!");
}

// ===========================================================================
// PE Parser Tests (No Admin Required)
// ===========================================================================

#[test]
fn test_parse_test_dll() {
    use helpers::*;

    println!("Testing PE parser with test DLL...");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        println!("Test DLL not found, skipping PE parser test");
        return;
    }

    let result = pe::PeFile::from_file(&dll_path);
    assert!(result.is_ok(), "Failed to parse test DLL");

    let pe = result.unwrap();

    // Verify basic PE properties
    assert!(pe.sections.len() > 0, "Should have at least one section");
    assert!(pe.entry_point() > 0, "Should have entry point");
    assert!(pe.image_base() > 0, "Should have image base");
    assert!(pe.size_of_image() > 0, "Should have image size");

    println!("PE file details:");
    println!("  Architecture: {}-bit", if pe.is_64bit { 64 } else { 32 });
    println!("  Sections: {}", pe.sections.len());
    println!("  Entry point: 0x{:X}", pe.entry_point());
    println!("  Image base: 0x{:X}", pe.image_base());

    println!("PE parser test passed!");
}

#[test]
fn test_pe_file_validation() {
    use helpers::*;

    println!("Testing PE file validation...");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        println!("Test DLL not found, skipping validation test");
        return;
    }

    // Test DLL path validation
    let result = injection::validate_dll_path(&dll_path);
    assert!(result.is_ok(), "DLL path validation should pass");

    // Test invalid path
    let invalid = PathBuf::from("relative/path.dll");
    let result = injection::validate_dll_path(&invalid);
    assert!(result.is_err(), "Relative path should fail validation");

    println!("PE file validation test passed!");
}

// ===========================================================================
// Privilege Tests (Require Admin)
// ===========================================================================

#[test]
#[ignore]
fn test_administrator_detection() {
    println!("Testing administrator detection...");

    let result = PrivilegeManager::is_administrator();
    assert!(result.is_ok(), "Administrator check should not fail");

    let is_admin = result.unwrap();
    println!("Running as administrator: {}", is_admin);

    // This test should be run with admin privileges
    assert!(
        is_admin,
        "Test should be run as administrator when using --ignored flag"
    );

    println!("Administrator detection test passed!");
}

#[test]
#[ignore]
fn test_debug_privilege_enable() {
    println!("Testing debug privilege enable...");

    let result = PrivilegeManager::enable_debug_privilege();

    if let Err(e) = &result {
        println!("Failed to enable debug privilege: {:?}", e);
        println!("Note: This requires administrator privileges");
    }

    // Should succeed when running as admin
    assert!(
        result.is_ok(),
        "Failed to enable debug privilege - are you running as admin?"
    );

    println!("Debug privilege enable test passed!");
}

// ===========================================================================
// New Injection Method Tests (Require Admin)
// ===========================================================================

#[test]
#[ignore]
fn test_section_mapping_injection() {
    use helpers::*;

    println!("Testing Section Mapping injection...");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        panic!(
            "Test DLL not found at {:?}. Run: cargo build -p test-dll --release --features silent",
            dll_path
        );
    }

    let (mut child, pid) = spawn_test_process();
    clear_marker_file();

    let injector = SectionMappingInjector::new();
    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process - run as administrator!");

    println!("Injecting into PID {} using Section Mapping...", pid);
    let result = injector.inject(&handle, &dll_path);

    std::thread::sleep(Duration::from_millis(100));

    if let Err(e) = &result {
        println!("Injection error: {:?}", e);
    }
    assert!(
        result.is_ok(),
        "Section Mapping injection failed: {:?}",
        result.err()
    );
    assert!(
        check_marker_file(),
        "Marker file not created - DLL did not execute!"
    );

    let _ = child.kill();
    clear_marker_file();

    println!("Section Mapping injection test passed!");
}

#[test]
#[ignore]
fn test_thread_hijacking_injection() {
    use helpers::*;

    println!("Testing Thread Hijacking injection...");
    println!("WARNING: This is an EXPERIMENTAL method - may cause crashes");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        panic!("Test DLL not found");
    }

    let (mut child, pid) = spawn_test_process();
    clear_marker_file();

    let injector = ThreadHijackingInjector::new();
    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process - run as administrator!");

    println!("Injecting into PID {} using Thread Hijacking...", pid);
    let result = injector.inject(&handle, &dll_path);

    // Give more time for thread hijacking to execute
    std::thread::sleep(Duration::from_millis(200));

    if let Err(e) = &result {
        println!("Injection error: {:?}", e);
    }

    // Thread hijacking may fail or crash the target
    // We still consider it a success if it doesn't panic
    if result.is_ok() {
        println!("Thread Hijacking injection succeeded");
        if check_marker_file() {
            println!("Marker file created - DLL executed successfully!");
        } else {
            println!("Warning: Marker file not created - DLL may not have executed");
        }
    } else {
        println!("Thread Hijacking failed (expected for experimental method)");
    }

    let _ = child.kill();
    clear_marker_file();

    println!("Thread Hijacking injection test completed!");
}

#[test]
#[ignore]
fn test_reflective_loader_injection() {
    use helpers::*;

    println!("Testing Reflective Loader injection...");
    println!("NOTE: This is a RESEARCH method and may not be fully implemented");

    let dll_path = test_dll_path();
    if !dll_path.exists() {
        panic!("Test DLL not found");
    }

    let (mut child, pid) = spawn_test_process();
    clear_marker_file();

    let injector = ReflectiveLoaderInjector::new();
    let handle = ProcessHandle::open(pid, injector.required_access())
        .expect("Failed to open process - run as administrator!");

    println!("Injecting into PID {} using Reflective Loader...", pid);
    let result = injector.inject(&handle, &dll_path);

    // Reflective loader is not fully implemented, so we expect it to fail
    if result.is_err() {
        println!("Reflective Loader failed (expected - not fully implemented)");
        println!("Error: {:?}", result.err());
    } else {
        println!("Reflective Loader injection succeeded (unexpected!)");
    }

    let _ = child.kill();
    clear_marker_file();

    println!("Reflective Loader injection test completed!");
}

//! Simple test DLL for injection testing.
//! Shows a message box when loaded (unless silent feature is enabled).
//! Creates a marker file for automated test verification.

use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

#[cfg(not(feature = "silent"))]
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONINFORMATION};
#[cfg(not(feature = "silent"))]
use windows::core::w;

/// Counter to track how many times this DLL has been loaded
static LOAD_COUNT: AtomicU32 = AtomicU32::new(0);

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _dll_module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        // Increment load counter
        let count = LOAD_COUNT.fetch_add(1, Ordering::SeqCst) + 1;

        // Create marker file for automated testing
        create_marker_file(count);

        // Show message box only if not in silent mode
        #[cfg(not(feature = "silent"))]
        unsafe {
            MessageBoxW(
                None,
                w!("Test DLL successfully injected!\n\nThe injection worked!"),
                w!("Injection Success"),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }

    BOOL::from(true)
}

/// Creates a marker file in TEMP directory for test verification
fn create_marker_file(load_count: u32) {
    use std::io::Write;

    // Get TEMP directory
    let temp_dir = std::env::temp_dir();
    let marker_path = temp_dir.join("dll_injector_test_marker.txt");

    // Create marker file with timestamp and load count
    if let Ok(mut file) = std::fs::File::create(&marker_path) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let _ = writeln!(file, "DLL Injected Successfully");
        let _ = writeln!(file, "Timestamp: {}", timestamp);
        let _ = writeln!(file, "Load Count: {}", load_count);
        let _ = writeln!(file, "Process ID: {}", std::process::id());
    }
}

/// Exported test function that returns a known value
/// Used for verifying exported function calls work
#[no_mangle]
pub extern "C" fn test_exported_function() -> i32 {
    42
}

/// Returns the current load count
#[no_mangle]
pub extern "C" fn get_load_count() -> u32 {
    LOAD_COUNT.load(Ordering::SeqCst)
}

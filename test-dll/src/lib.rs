//! Simple test DLL for injection testing.
//! Shows a message box when loaded.

use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONINFORMATION};
use windows::core::w;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _dll_module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        // Show message box when DLL is loaded
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

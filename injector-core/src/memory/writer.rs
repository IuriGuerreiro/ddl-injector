//! Writing data to remote process memory.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use crate::InjectionError;

/// Write data to a remote process's memory.
///
/// # Arguments
/// * `process` - Target process handle
/// * `address` - Address to write to
/// * `data` - Data to write
///
/// # Errors
/// Returns `InjectionError::MemoryWriteFailed` if write fails.
///
/// # Safety
/// The caller must ensure:
/// - `address` is valid in the remote process
/// - Remote memory is large enough to hold `data`
/// - Remote memory has write permissions
pub fn write_memory(
    process: HANDLE,
    address: *mut u8,
    data: &[u8],
) -> Result<(), InjectionError> {
    let mut bytes_written = 0;

    unsafe {
        WriteProcessMemory(
            process,
            address as *const std::ffi::c_void,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            Some(&mut bytes_written),
        )
        .map_err(|_| InjectionError::MemoryWriteFailed(
            std::io::Error::last_os_error()
        ))?;
    }

    if bytes_written != data.len() {
        log::warn!(
            "Partial write: {} of {} bytes written",
            bytes_written,
            data.len()
        );
        return Err(InjectionError::MemoryWriteFailed(
            std::io::Error::other("Incomplete write operation")
        ));
    }

    log::debug!(
        "Wrote {} bytes to {:?} in remote process",
        bytes_written,
        address
    );

    Ok(())
}

/// Write a wide string (UTF-16) to remote memory.
pub fn write_wide_string(
    process: HANDLE,
    address: *mut u8,
    text: &str,
) -> Result<(), InjectionError> {
    // Convert to UTF-16
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();

    // Write as bytes
    let bytes = unsafe {
        std::slice::from_raw_parts(
            wide.as_ptr() as *const u8,
            wide.len() * 2,
        )
    };

    write_memory(process, address, bytes)
}

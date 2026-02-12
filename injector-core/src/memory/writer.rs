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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::GetCurrentProcess;
    use crate::memory::allocator::RemoteMemory;
    use crate::memory::reader::read_memory_vec;
    use windows::Win32::System::Memory::PAGE_READWRITE;

    #[test]
    fn test_write_memory_to_own_process() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        let test_data = b"Hello from write_memory!";
        let result = write_memory(process, mem.address(), test_data);

        assert!(result.is_ok());

        // Verify by reading back
        let read_back = unsafe {
            read_memory_vec(process, mem.address(), test_data.len())
        };
        assert_eq!(&read_back.unwrap()[..], test_data);
    }

    #[test]
    fn test_write_wide_string() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        let test_string = "Hello, UTF-16!";
        let result = write_wide_string(process, mem.address(), test_string);

        assert!(result.is_ok());

        // Verify by reading back
        let expected_wide: Vec<u16> = test_string
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let expected_bytes = unsafe {
            std::slice::from_raw_parts(
                expected_wide.as_ptr() as *const u8,
                expected_wide.len() * 2,
            )
        };

        let read_back = unsafe {
            read_memory_vec(process, mem.address(), expected_bytes.len())
        };

        assert_eq!(&read_back.unwrap()[..], expected_bytes);
    }

    #[test]
    fn test_write_wide_string_null_terminator() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        let test_string = "Test";
        write_wide_string(process, mem.address(), test_string)
            .expect("Failed to write wide string");

        // Read back and verify null terminator
        let expected_len = (test_string.len() + 1) * 2; // +1 for null terminator
        let read_back = unsafe {
            read_memory_vec(process, mem.address(), expected_len)
        };

        let read_back = read_back.unwrap();

        // Last two bytes should be null (UTF-16 null terminator)
        assert_eq!(read_back[read_back.len() - 2], 0);
        assert_eq!(read_back[read_back.len() - 1], 0);
    }

    #[test]
    fn test_write_memory_various_sizes() {
        let process = unsafe { GetCurrentProcess() };

        // Test different sizes
        for size in [1, 8, 64, 512] {
            let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
                .expect("Failed to allocate memory");

            let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let result = write_memory(process, mem.address(), &test_data);

            assert!(result.is_ok());

            // Verify
            let read_back = unsafe {
                read_memory_vec(process, mem.address(), size)
            };
            assert_eq!(read_back.unwrap(), test_data);
        }
    }

    #[test]
    fn test_write_memory_empty() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        let empty_data: &[u8] = &[];
        let result = write_memory(process, mem.address(), empty_data);

        // Writing empty data should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_wide_string_unicode() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        // Test with Unicode characters
        let test_string = "Hello 世界 🌍";
        let result = write_wide_string(process, mem.address(), test_string);

        assert!(result.is_ok());

        // Verify the data was written correctly
        let expected_wide: Vec<u16> = test_string
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let expected_bytes = unsafe {
            std::slice::from_raw_parts(
                expected_wide.as_ptr() as *const u8,
                expected_wide.len() * 2,
            )
        };

        let read_back = unsafe {
            read_memory_vec(process, mem.address(), expected_bytes.len())
        };

        assert_eq!(&read_back.unwrap()[..], expected_bytes);
    }
}

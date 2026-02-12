//! Reading data from remote process memory.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use crate::InjectionError;

/// Read data from a remote process's memory.
///
/// # Arguments
/// * `process` - Target process handle
/// * `address` - Address to read from
/// * `buffer` - Buffer to read into
///
/// # Errors
/// Returns `InjectionError::MemoryReadFailed` if read fails.
pub fn read_memory(
    process: HANDLE,
    address: *const std::ffi::c_void,
    buffer: &mut [u8],
) -> Result<(), InjectionError> {
    let mut bytes_read = 0;

    unsafe {
        ReadProcessMemory(
            process,
            address,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            Some(&mut bytes_read),
        )
        .map_err(|_| InjectionError::MemoryReadFailed(
            std::io::Error::last_os_error()
        ))?;
    }

    if bytes_read != buffer.len() {
        return Err(InjectionError::MemoryReadFailed(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Incomplete read operation"
            )
        ));
    }

    Ok(())
}

/// Read data from remote memory, returning a Vec.
pub fn read_memory_vec(
    process: HANDLE,
    address: *const u8,
    size: usize,
) -> Result<Vec<u8>, InjectionError> {
    let mut buffer = vec![0u8; size];
    read_memory(process, address as *const std::ffi::c_void, &mut buffer)?;
    Ok(buffer)
}

/// Read a structure from remote memory.
///
/// # Safety
/// The caller must ensure `T` is safe to construct from arbitrary bytes.
pub unsafe fn read_struct<T: Copy>(
    process: HANDLE,
    address: *const u8,
) -> Result<T, InjectionError> {
    let mut buffer = vec![0u8; std::mem::size_of::<T>()];
    read_memory(process, address as *const std::ffi::c_void, &mut buffer)?;
    Ok(*(buffer.as_ptr() as *const T))
}
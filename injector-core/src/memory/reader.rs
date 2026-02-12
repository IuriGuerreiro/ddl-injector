//! Reading data from remote process memory.

use crate::InjectionError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

/// Read data from a remote process's memory.
///
/// # Arguments
/// * `process` - Target process handle
/// * `address` - Address to read from
/// * `buffer` - Buffer to read into
///
/// # Safety
/// This function dereferences the raw pointer `address`.
///
/// # Errors
/// Returns `InjectionError::MemoryReadFailed` if read fails.
pub unsafe fn read_memory(
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
        .map_err(|_| InjectionError::MemoryReadFailed(std::io::Error::last_os_error()))?;
    }

    if bytes_read != buffer.len() {
        return Err(InjectionError::MemoryReadFailed(std::io::Error::other(
            "Incomplete read operation",
        )));
    }

    Ok(())
}

/// Read data from remote memory, returning a Vec.
///
/// # Safety
/// This function dereferences the raw pointer `address`.
pub unsafe fn read_memory_vec(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::allocator::RemoteMemory;
    use crate::memory::writer::write_memory;
    use windows::Win32::System::Memory::PAGE_READWRITE;
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[test]
    fn test_read_memory_from_own_process() {
        let process = unsafe { GetCurrentProcess() };

        // Allocate some memory in our own process
        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        // Write some test data
        let test_data = b"Hello, World!";
        write_memory(process, mem.address(), test_data).expect("Failed to write memory");

        // Read it back
        let mut buffer = vec![0u8; test_data.len()];
        unsafe {
            read_memory(
                process,
                mem.address() as *const std::ffi::c_void,
                &mut buffer,
            )
            .expect("Failed to read memory");
        }

        assert_eq!(&buffer[..], test_data);
    }

    #[test]
    fn test_read_memory_vec() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        let test_data = b"Test data for read_memory_vec";
        write_memory(process, mem.address(), test_data).expect("Failed to write memory");

        let result = unsafe { read_memory_vec(process, mem.address(), test_data.len()) };

        assert!(result.is_ok());
        assert_eq!(&result.unwrap()[..], test_data);
    }

    #[test]
    fn test_read_struct() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        // Test structure
        #[repr(C)]
        #[derive(Copy, Clone, Debug, PartialEq)]
        struct TestStruct {
            a: u32,
            b: u64,
            c: u16,
        }

        let test_value = TestStruct {
            a: 0x12345678,
            b: 0xDEADBEEFCAFEBABE,
            c: 0xABCD,
        };

        // Write struct
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &test_value as *const TestStruct as *const u8,
                std::mem::size_of::<TestStruct>(),
            )
        };
        write_memory(process, mem.address(), bytes).expect("Failed to write struct");

        // Read struct back
        let result: TestStruct =
            unsafe { read_struct(process, mem.address()).expect("Failed to read struct") };

        assert_eq!(result, test_value);
    }

    #[test]
    fn test_read_memory_various_sizes() {
        let process = unsafe { GetCurrentProcess() };

        // Test with different sizes
        for size in [1, 4, 8, 16, 64, 256, 1024] {
            let mem = RemoteMemory::allocate(process, size, PAGE_READWRITE)
                .expect("Failed to allocate memory");

            let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            write_memory(process, mem.address(), &test_data).expect("Failed to write memory");

            let result = unsafe { read_memory_vec(process, mem.address(), size) };

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), test_data);
        }
    }

    #[test]
    fn test_read_memory_invalid_address() {
        let process = unsafe { GetCurrentProcess() };

        // Try to read from null pointer (should fail)
        let mut buffer = vec![0u8; 10];
        let result = unsafe { read_memory(process, std::ptr::null(), &mut buffer) };

        assert!(result.is_err());
    }

    #[test]
    fn test_read_struct_primitive_types() {
        let process = unsafe { GetCurrentProcess() };

        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        // Test with u64
        let test_u64: u64 = 0x123456789ABCDEF0;
        write_memory(process, mem.address(), &test_u64.to_le_bytes()).expect("Failed to write u64");

        let result: u64 =
            unsafe { read_struct(process, mem.address()).expect("Failed to read u64") };

        assert_eq!(result, test_u64);
    }
}

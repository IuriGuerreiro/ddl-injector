//! Remote memory allocation with RAII cleanup.

use crate::InjectionError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::*;

/// RAII wrapper for remotely allocated memory.
///
/// Automatically frees memory when dropped.
pub struct RemoteMemory {
    process: HANDLE,
    address: *mut u8,
    size: usize,
}

impl RemoteMemory {
    /// Allocate memory in the target process.
    ///
    /// # Arguments
    /// * `process` - Target process handle
    /// * `size` - Number of bytes to allocate
    /// * `protection` - Memory protection flags
    ///
    /// # Errors
    /// Returns `InjectionError::MemoryAllocationFailed` on failure.
    pub fn allocate(
        process: HANDLE,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<Self, InjectionError> {
        let address =
            unsafe { VirtualAllocEx(process, None, size, MEM_COMMIT | MEM_RESERVE, protection) };

        if address.is_null() {
            return Err(InjectionError::MemoryAllocationFailed(
                std::io::Error::last_os_error(),
            ));
        }

        log::debug!(
            "Allocated {} bytes at {:?} in remote process",
            size,
            address
        );

        Ok(Self {
            process,
            address: address as *mut u8,
            size,
        })
    }

    /// Get the address of the allocated memory.
    pub fn address(&self) -> *mut u8 {
        self.address
    }

    /// Allocate executable memory in the target process.
    ///
    /// This is a convenience method that allocates memory with PAGE_EXECUTE_READWRITE protection.
    ///
    /// # Arguments
    /// * `process` - Target process handle
    /// * `size` - Number of bytes to allocate
    ///
    /// # Errors
    /// Returns `InjectionError::MemoryAllocationFailed` on failure.
    pub fn allocate_executable(process: HANDLE, size: usize) -> Result<Self, InjectionError> {
        Self::allocate(process, size, PAGE_EXECUTE_READWRITE)
    }

    /// Get the size of the allocation.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Convert to raw pointer (for FFI).
    pub fn as_ptr(&self) -> *const std::ffi::c_void {
        self.address as *const std::ffi::c_void
    }
}

impl Drop for RemoteMemory {
    fn drop(&mut self) {
        unsafe {
            let result = VirtualFreeEx(
                self.process,
                self.address as *mut std::ffi::c_void,
                0,
                MEM_RELEASE,
            );

            if let Err(e) = result {
                log::warn!("Failed to free remote memory at {:?}: {}", self.address, e);
            } else {
                log::debug!("Freed remote memory at {:?}", self.address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[test]
    fn test_allocate_in_own_process() {
        let process = unsafe { GetCurrentProcess() };
        let size = 4096;

        let mem = RemoteMemory::allocate(process, size, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        assert!(!mem.address().is_null());
        assert_eq!(mem.size(), size);
    }

    #[test]
    fn test_allocate_executable() {
        let process = unsafe { GetCurrentProcess() };
        let size = 1024;

        let mem = RemoteMemory::allocate_executable(process, size)
            .expect("Failed to allocate executable memory");

        assert!(!mem.address().is_null());
        assert_eq!(mem.size(), size);
    }

    #[test]
    fn test_address_accessor() {
        let process = unsafe { GetCurrentProcess() };
        let mem = RemoteMemory::allocate(process, 512, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        let addr = mem.address();
        assert!(!addr.is_null());
    }

    #[test]
    fn test_size_accessor() {
        let process = unsafe { GetCurrentProcess() };
        let expected_size = 2048;

        let mem = RemoteMemory::allocate(process, expected_size, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        assert_eq!(mem.size(), expected_size);
    }

    #[test]
    fn test_as_ptr() {
        let process = unsafe { GetCurrentProcess() };
        let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
            .expect("Failed to allocate memory");

        let ptr = mem.as_ptr();
        assert!(!ptr.is_null());
    }

    #[test]
    fn test_raii_cleanup() {
        let process = unsafe { GetCurrentProcess() };
        let addr: *mut u8;

        {
            let mem = RemoteMemory::allocate(process, 1024, PAGE_READWRITE)
                .expect("Failed to allocate memory");
            addr = mem.address();
            assert!(!addr.is_null());
        } // mem dropped here, should free memory

        // Memory should be freed, but we can't easily verify this without
        // causing a potential access violation. The test passes if no crash occurs.
    }

    #[test]
    fn test_allocate_with_different_protections() {
        let process = unsafe { GetCurrentProcess() };

        // Test different protection flags
        let mem_rw = RemoteMemory::allocate(process, 512, PAGE_READWRITE)
            .expect("Failed with PAGE_READWRITE");
        assert!(!mem_rw.address().is_null());

        let mem_r =
            RemoteMemory::allocate(process, 512, PAGE_READONLY).expect("Failed with PAGE_READONLY");
        assert!(!mem_r.address().is_null());

        let mem_ex = RemoteMemory::allocate(process, 512, PAGE_EXECUTE_READ)
            .expect("Failed with PAGE_EXECUTE_READ");
        assert!(!mem_ex.address().is_null());
    }

    #[test]
    fn test_allocate_zero_size() {
        let process = unsafe { GetCurrentProcess() };

        // Allocating 0 bytes should fail
        let result = RemoteMemory::allocate(process, 0, PAGE_READWRITE);
        assert!(result.is_err());
    }
}

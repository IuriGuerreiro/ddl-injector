//! Remote memory allocation with RAII cleanup.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::*;
use crate::InjectionError;

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
        let address = unsafe {
            VirtualAllocEx(
                process,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                protection,
            )
        };

        if address.is_null() {
            return Err(InjectionError::MemoryAllocationFailed(
                std::io::Error::last_os_error()
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
    pub fn allocate_executable(
        process: HANDLE,
        size: usize,
    ) -> Result<Self, InjectionError> {
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
                log::warn!(
                    "Failed to free remote memory at {:?}: {}",
                    self.address,
                    e
                );
            } else {
                log::debug!("Freed remote memory at {:?}", self.address);
            }
        }
    }
}

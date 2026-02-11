// Process handle management

use crate::error::ProcessError;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};

/// A handle to an open process
///
/// This struct provides RAII (Resource Acquisition Is Initialization) semantics
/// for Windows process handles, ensuring they are automatically closed when dropped.
pub struct ProcessHandle {
    handle: HANDLE,
    pid: u32,
}

// Process handles can be safely moved between threads
unsafe impl Send for ProcessHandle {}

impl ProcessHandle {
    /// Opens a process with the specified access rights
    ///
    /// # Arguments
    /// * `pid` - The process ID to open
    /// * `rights` - The desired access rights for the process handle
    ///
    /// # Returns
    /// * `Ok(ProcessHandle)` - Successfully opened process handle
    /// * `Err(ProcessError::OpenProcessFailed)` - Failed to open process or invalid handle
    ///
    /// # Example
    /// ```no_run
    /// # use injector_core::process::ProcessHandle;
    /// # use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let handle = ProcessHandle::open(1234, PROCESS_QUERY_INFORMATION)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn open(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Result<Self, ProcessError> {
        unsafe {
            let handle = OpenProcess(rights, false, pid);

            match handle {
                Ok(h) if h.is_invalid() => {
                    Err(ProcessError::OpenProcessFailed(
                        std::io::Error::last_os_error(),
                    ))
                }
                Ok(h) => Ok(Self {
                    handle: h,
                    pid,
                }),
                Err(_) => Err(ProcessError::OpenProcessFailed(
                    std::io::Error::last_os_error(),
                )),
            }
        }
    }

    /// Returns the process ID associated with this handle
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the raw Windows handle
    ///
    /// # Safety
    /// The caller must ensure they do not use this handle after the ProcessHandle is dropped.
    pub fn as_handle(&self) -> HANDLE {
        self.handle
    }

    /// Checks if the handle is valid
    ///
    /// # Returns
    /// * `true` if the handle is valid
    /// * `false` if the handle is invalid
    pub fn is_valid(&self) -> bool {
        !self.handle.is_invalid()
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

    #[test]
    fn test_open_current_process() {
        let pid = std::process::id();
        let handle = ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION);

        assert!(handle.is_ok(), "Should be able to open current process");
        let handle = handle.unwrap();
        assert!(handle.is_valid(), "Handle should be valid");
        assert_eq!(handle.pid(), pid, "PID should match");
    }

    #[test]
    fn test_open_invalid_pid() {
        // PID 0 is never a valid user process
        let result = ProcessHandle::open(0, PROCESS_QUERY_INFORMATION);

        assert!(result.is_err(), "Opening PID 0 should fail");
        match result {
            Err(ProcessError::OpenProcessFailed(_)) => {
                // Expected error
            }
            _ => panic!("Expected OpenProcessFailed error"),
        }
    }

    #[test]
    fn test_is_valid() {
        let pid = std::process::id();
        let handle = ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION).unwrap();

        assert!(handle.is_valid(), "Valid handle should report as valid");
    }

    #[test]
    fn test_multiple_opens() {
        let pid = std::process::id();

        // Open the same process twice
        let handle1 = ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION);
        let handle2 = ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION);

        assert!(handle1.is_ok(), "First open should succeed");
        assert!(handle2.is_ok(), "Second open should succeed");

        // Both handles should be valid and different
        let h1 = handle1.unwrap();
        let h2 = handle2.unwrap();

        assert!(h1.is_valid());
        assert!(h2.is_valid());

        // The raw handles should be different (different kernel objects)
        assert_ne!(
            h1.as_handle().0,
            h2.as_handle().0,
            "Different opens should yield different handles"
        );
    }

    #[test]
    fn test_invalid_pid_range() {
        // Try an extremely high PID that's very unlikely to exist
        let result = ProcessHandle::open(u32::MAX - 1, PROCESS_QUERY_INFORMATION);

        assert!(result.is_err(), "Opening non-existent PID should fail");
    }

    #[test]
    fn test_drop_cleanup() {
        let pid = std::process::id();

        // Create a handle in a scope so it gets dropped
        {
            let _handle = ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION)
                .expect("Should open current process");
            // Handle is valid here
        }
        // Handle has been dropped and cleaned up

        // If we can open the process again, the previous handle was properly cleaned up
        let handle = ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION);
        assert!(handle.is_ok(), "Should be able to open process after previous handle dropped");
    }
}

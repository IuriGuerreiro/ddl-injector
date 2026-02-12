//! Thread enumeration and management.

use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use crate::error::ProcessError;

/// Information about a thread.
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub base_priority: i32,
}

/// RAII wrapper for thread handle.
pub struct ThreadHandle {
    handle: HANDLE,
}

impl ThreadHandle {
    /// Open a thread by ID.
    pub fn open(thread_id: u32, access: THREAD_ACCESS_RIGHTS) -> Result<Self, ProcessError> {
        let handle = unsafe {
            OpenThread(access, false, thread_id)
                .map_err(|_| ProcessError::OpenThreadFailed(
                    std::io::Error::last_os_error()
                ))?
        };

        Ok(Self { handle })
    }

    /// Get raw handle.
    pub fn as_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_invalid() {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// Thread enumerator.
pub struct ThreadEnumerator;

impl ThreadEnumerator {
    /// Enumerate all threads belonging to a process.
    pub fn enumerate(process_id: u32) -> Result<Vec<ThreadInfo>, ProcessError> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|_| ProcessError::ThreadSnapshotFailed(
                    std::io::Error::last_os_error()
                ))?
        };

        let _guard = SnapshotGuard(snapshot);

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        unsafe {
            Thread32First(snapshot, &mut entry)
                .map_err(|_| ProcessError::ThreadEnumerationFailed(
                    std::io::Error::last_os_error()
                ))?;
        }

        let mut threads = Vec::new();

        loop {
            if entry.th32OwnerProcessID == process_id {
                threads.push(ThreadInfo {
                    thread_id: entry.th32ThreadID,
                    owner_process_id: entry.th32OwnerProcessID,
                    base_priority: entry.tpBasePri,
                });
            }

            if unsafe { Thread32Next(snapshot, &mut entry).is_err() } {
                break;
            }
        }

        log::debug!("Found {} threads for PID {}", threads.len(), process_id);
        Ok(threads)
    }
}

struct SnapshotGuard(HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_threads_own_process() {
        let pid = std::process::id();

        let result = ThreadEnumerator::enumerate(pid);
        assert!(result.is_ok());

        let threads = result.unwrap();

        // Should have at least one thread (current thread)
        assert!(threads.len() >= 1);

        // All threads should belong to our process
        for thread in &threads {
            assert_eq!(thread.owner_process_id, pid);
        }
    }

    #[test]
    fn test_thread_info_fields() {
        let pid = std::process::id();

        let threads = ThreadEnumerator::enumerate(pid).unwrap();

        if let Some(thread) = threads.first() {
            // Thread ID should be non-zero
            assert!(thread.thread_id > 0);

            // Owner PID should match
            assert_eq!(thread.owner_process_id, pid);

            // Base priority should be reasonable (typically 0-31)
            assert!(thread.base_priority >= -2 && thread.base_priority <= 31);
        }
    }

    #[test]
    fn test_open_thread() {
        let pid = std::process::id();
        let threads = ThreadEnumerator::enumerate(pid).unwrap();

        if let Some(thread) = threads.first() {
            let result = ThreadHandle::open(
                thread.thread_id,
                THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            );

            assert!(result.is_ok());

            let handle = result.unwrap();
            assert!(!handle.as_handle().is_invalid());
        }
    }

    #[test]
    fn test_thread_handle_raii() {
        let pid = std::process::id();
        let threads = ThreadEnumerator::enumerate(pid).unwrap();

        if let Some(thread) = threads.first() {
            let handle_value;

            {
                let handle = ThreadHandle::open(
                    thread.thread_id,
                    THREAD_QUERY_INFORMATION,
                ).unwrap();

                handle_value = handle.as_handle();
                assert!(!handle_value.is_invalid());
            } // handle dropped here, should close

            // Can't easily verify handle is closed without causing errors,
            // but test passes if no crash occurs
        }
    }

    #[test]
    fn test_enumerate_invalid_process() {
        // Try to enumerate threads for a process that definitely doesn't exist
        let result = ThreadEnumerator::enumerate(0xFFFFFFFF);

        // Should succeed but return empty list (no threads for invalid PID)
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_open_invalid_thread() {
        // Try to open a thread that doesn't exist
        let result = ThreadHandle::open(0xFFFFFFFF, THREAD_QUERY_INFORMATION);

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_thread_enumeration_multiple_calls() {
        let pid = std::process::id();

        // Call enumerate multiple times
        let threads1 = ThreadEnumerator::enumerate(pid).unwrap();
        let threads2 = ThreadEnumerator::enumerate(pid).unwrap();

        // Both should succeed and have similar counts
        // (may not be exactly the same due to thread creation/destruction)
        assert!(threads1.len() > 0);
        assert!(threads2.len() > 0);
    }
}

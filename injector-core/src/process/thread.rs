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

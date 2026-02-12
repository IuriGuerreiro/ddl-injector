// Process enumeration functionality

use crate::error::ProcessError;
use crate::process::ProcessInfo;
use std::mem;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// Enumerates running processes on the system
pub struct ProcessEnumerator;

impl ProcessEnumerator {
    /// Enumerates all running processes on the system
    ///
    /// # Returns
    /// * `Ok(Vec<ProcessInfo>)` - List of all discovered processes
    /// * `Err(ProcessError)` - If snapshot creation or enumeration fails
    ///
    /// # Example
    /// ```no_run
    /// # use injector_core::process::ProcessEnumerator;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let processes = ProcessEnumerator::enumerate()?;
    /// for process in processes {
    ///     println!("{}", process);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn enumerate() -> Result<Vec<ProcessInfo>, ProcessError> {
        unsafe {
            // Create a snapshot of all processes
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| {
                ProcessError::SnapshotFailed(std::io::Error::from_raw_os_error(e.code().0))
            })?;

            // Use RAII guard to ensure snapshot is closed
            let _guard = SnapshotGuard(snapshot);

            let mut processes = Vec::new();
            let mut entry: PROCESSENTRY32W = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

            // Get the first process
            if Process32FirstW(snapshot, &mut entry).is_err() {
                return Err(ProcessError::EnumerationFailed(
                    std::io::Error::last_os_error(),
                ));
            }

            // Add the first process
            processes.push(ProcessInfo::from_entry(&entry));

            // Enumerate remaining processes
            loop {
                entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

                match Process32NextW(snapshot, &mut entry) {
                    Ok(_) => {
                        processes.push(ProcessInfo::from_entry(&entry));
                    }
                    Err(_) => {
                        // No more processes
                        break;
                    }
                }
            }

            Ok(processes)
        }
    }

    /// Finds a process by its process ID (PID)
    ///
    /// # Arguments
    /// * `pid` - The process ID to search for
    ///
    /// # Returns
    /// * `Ok(ProcessInfo)` - The process with the matching PID
    /// * `Err(ProcessError::ProcessNotFound)` - If no process with that PID exists
    ///
    /// # Example
    /// ```no_run
    /// # use injector_core::process::ProcessEnumerator;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let process = ProcessEnumerator::find_by_pid(1234)?;
    /// println!("Found: {}", process);
    /// # Ok(())
    /// # }
    /// ```
    pub fn find_by_pid(pid: u32) -> Result<ProcessInfo, ProcessError> {
        let processes = Self::enumerate()?;

        processes
            .into_iter()
            .find(|p| p.pid == pid)
            .ok_or(ProcessError::ProcessNotFound(pid))
    }

    /// Finds all processes matching the given name (case-insensitive substring match)
    ///
    /// # Arguments
    /// * `name` - The process name or substring to search for (case-insensitive)
    ///
    /// # Returns
    /// * `Ok(Vec<ProcessInfo>)` - List of all matching processes (may be empty)
    /// * `Err(ProcessError)` - If enumeration fails
    ///
    /// # Example
    /// ```no_run
    /// # use injector_core::process::ProcessEnumerator;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let processes = ProcessEnumerator::find_by_name("notepad")?;
    /// for process in processes {
    ///     println!("Found: {}", process);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn find_by_name(name: &str) -> Result<Vec<ProcessInfo>, ProcessError> {
        let processes = Self::enumerate()?;
        let name_lower = name.to_lowercase();

        Ok(processes
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&name_lower))
            .collect())
    }
}

/// RAII guard for automatic snapshot handle cleanup
struct SnapshotGuard(HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::GetCurrentProcessId;

    #[test]
    fn test_enumerate_processes() {
        let processes = ProcessEnumerator::enumerate();

        assert!(processes.is_ok(), "Should be able to enumerate processes");

        let processes = processes.unwrap();
        assert!(!processes.is_empty(), "Should find at least one process");

        // We should find our own process
        let current_pid = unsafe { GetCurrentProcessId() };
        let found = processes.iter().any(|p| p.pid == current_pid);

        assert!(
            found,
            "Should find current process (PID: {}) in enumeration",
            current_pid
        );
    }

    #[test]
    fn test_find_by_pid() {
        let current_pid = unsafe { GetCurrentProcessId() };
        let result = ProcessEnumerator::find_by_pid(current_pid);

        assert!(
            result.is_ok(),
            "Should find current process by PID: {}",
            current_pid
        );

        let process = result.unwrap();
        assert_eq!(process.pid, current_pid, "PID should match");
        assert!(!process.name.is_empty(), "Process name should not be empty");
    }

    #[test]
    fn test_find_by_name() {
        // Search for processes containing "exe" in their name
        // This should match most Windows processes (e.g., svchost.exe, explorer.exe)
        let result = ProcessEnumerator::find_by_name("exe");

        assert!(result.is_ok(), "Should be able to search by name");

        let processes = result.unwrap();
        assert!(
            !processes.is_empty(),
            "Should find at least one process with 'exe' in the name"
        );

        // Verify all results contain the search term
        for process in &processes {
            assert!(
                process.name.to_lowercase().contains("exe"),
                "Process '{}' should contain 'exe'",
                process.name
            );
        }
    }

    #[test]
    fn test_find_invalid_pid() {
        // Use an invalid PID that's very unlikely to exist
        let result = ProcessEnumerator::find_by_pid(u32::MAX - 1);

        assert!(result.is_err(), "Should not find invalid PID");

        match result {
            Err(ProcessError::ProcessNotFound(pid)) => {
                assert_eq!(pid, u32::MAX - 1, "Error should contain the searched PID");
            }
            _ => panic!("Expected ProcessNotFound error"),
        }
    }
}

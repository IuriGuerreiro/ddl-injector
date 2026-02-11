// Process information structures

use crate::error::ProcessError;
use std::fmt;
use std::path::PathBuf;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::Foundation::CloseHandle;
use windows::core::PWSTR;

/// Information about a process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (e.g., "notepad.exe")
    pub name: String,
    /// Full executable path (if available)
    pub path: Option<PathBuf>,
    /// Parent process ID
    pub parent_pid: u32,
    /// Number of threads
    pub thread_count: u32,
}

impl ProcessInfo {
    /// Creates a ProcessInfo from a PROCESSENTRY32W snapshot entry
    pub fn from_entry(entry: &PROCESSENTRY32W) -> Self {
        // Find null terminator in wide string
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());

        // Convert wide string to Rust String
        let name = String::from_utf16_lossy(&entry.szExeFile[..len]);

        Self {
            pid: entry.th32ProcessID,
            name,
            path: None,
            parent_pid: entry.th32ParentProcessID,
            thread_count: entry.cntThreads,
        }
    }

    /// Attempts to retrieve the full executable path for this process
    /// Returns Ok(None) for protected processes without access
    pub fn try_get_path(&mut self) -> Result<(), ProcessError> {
        unsafe {
            // Open process with limited query permission
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                self.pid,
            );

            match handle {
                Ok(h) if h.is_invalid() => {
                    // Can't access this process, leave path as None
                    return Ok(());
                }
                Err(_) => {
                    // Can't access this process, leave path as None
                    return Ok(());
                }
                Ok(h) => {
                    // Query the full path
                    let mut buffer = [0u16; 260]; // MAX_PATH
                    let mut size = buffer.len() as u32;

                    let result = QueryFullProcessImageNameW(
                        h,
                        Default::default(),
                        PWSTR(buffer.as_mut_ptr()),
                        &mut size,
                    );

                    // Always close the handle
                    let _ = CloseHandle(h);

                    if result.is_ok() && size > 0 {
                        let path_str = String::from_utf16_lossy(&buffer[..size as usize]);
                        self.path = Some(PathBuf::from(path_str));
                    }

                    Ok(())
                }
            }
        }
    }
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Process {{ pid: {}, name: \"{}\", threads: {} }}",
            self.pid, self.name, self.thread_count
        )?;

        if let Some(ref path) = self.path {
            write!(f, " [{}]", path.display())?;
        }

        Ok(())
    }
}

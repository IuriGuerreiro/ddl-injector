// Windows privilege management implementation

use crate::error::PrivilegeError;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID, WIN32_ERROR};
use windows::Win32::Security::{
    AdjustTokenPrivileges, CheckTokenMembership, CreateWellKnownSid, GetTokenInformation,
    LookupPrivilegeValueW, TokenPrivileges, WinBuiltinAdministratorsSid, LUID_AND_ATTRIBUTES,
    PSID, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Manages Windows privileges for the current process.
pub struct PrivilegeManager;

impl PrivilegeManager {
    /// Checks if the current process is running with administrator privileges.
    ///
    /// This uses Windows security APIs to check if the process token is a member
    /// of the Administrators group.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if running as administrator
    /// - `Ok(false)` if not running as administrator
    /// - `Err` if the check fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use injector_core::PrivilegeManager;
    ///
    /// match PrivilegeManager::is_administrator() {
    ///     Ok(true) => println!("Running as administrator"),
    ///     Ok(false) => println!("Not running as administrator"),
    ///     Err(e) => eprintln!("Failed to check: {}", e),
    /// }
    /// ```
    pub fn is_administrator() -> Result<bool, PrivilegeError> {
        unsafe {
            // Get required size for SID
            let mut sid_size = 0u32;
            let _ = CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                None,
                PSID(std::ptr::null_mut()),
                &mut sid_size,
            );

            let mut sid_buffer = vec![0u8; sid_size as usize];

            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                None,
                PSID(sid_buffer.as_mut_ptr() as *mut _),
                &mut sid_size,
            )
            .map_err(|e| {
                log::error!("Failed to create well-known SID: {}", e);
                PrivilegeError::SidCreationFailed(std::io::Error::last_os_error())
            })?;

            // Check if current token is a member of Administrators group
            let mut is_member = Default::default();
            CheckTokenMembership(None, PSID(sid_buffer.as_ptr() as *mut _), &mut is_member).map_err(
                |e| {
                    log::error!("Failed to check token membership: {}", e);
                    PrivilegeError::MembershipCheckFailed(std::io::Error::last_os_error())
                },
            )?;

            log::debug!("Administrator check: {}", is_member.as_bool());
            Ok(is_member.as_bool())
        }
    }

    /// Enables SeDebugPrivilege for the current process.
    ///
    /// This privilege is required to open handles to processes owned by other users
    /// or protected system processes. Requires administrator privileges.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the privilege was successfully enabled
    /// - `Err(PrivilegeError::NotAdministrator)` if not running as administrator
    /// - `Err` for other failures
    ///
    /// # Example
    ///
    /// ```no_run
    /// use injector_core::PrivilegeManager;
    ///
    /// match PrivilegeManager::enable_debug_privilege() {
    ///     Ok(()) => println!("SeDebugPrivilege enabled"),
    ///     Err(e) => eprintln!("Failed to enable privilege: {}", e),
    /// }
    /// ```
    pub fn enable_debug_privilege() -> Result<(), PrivilegeError> {
        // Check if we're running as administrator first
        if !Self::is_administrator()? {
            log::warn!("Not running as administrator, cannot enable SeDebugPrivilege");
            return Err(PrivilegeError::NotAdministrator);
        }

        unsafe {
            // Open the process token
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .map_err(|e| {
                log::error!("Failed to open process token: {}", e);
                PrivilegeError::OpenTokenFailed(std::io::Error::last_os_error())
            })?;

            let _guard = TokenGuard(token);

            // Lookup the LUID for SeDebugPrivilege
            let mut luid = LUID::default();
            LookupPrivilegeValueW(None, windows::core::w!("SeDebugPrivilege"), &mut luid)
                .map_err(|e| {
                    log::error!("Failed to lookup privilege value: {}", e);
                    PrivilegeError::LookupPrivilegeFailed(std::io::Error::last_os_error())
                })?;

            // Set up the privilege structure
            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            // Adjust the token privileges
            AdjustTokenPrivileges(
                token,
                false,
                Some(&mut tp),
                0,
                None,
                None,
            )
            .map_err(|e| {
                log::error!("Failed to adjust token privileges: {}", e);
                PrivilegeError::AdjustPrivilegeFailed(std::io::Error::last_os_error())
            })?;

            // Check GetLastError for ERROR_NOT_ALL_ASSIGNED (1300)
            // This indicates the privilege is not held even if AdjustTokenPrivileges succeeded
            let last_error = GetLastError();
            if last_error.0 != 0 {
                if last_error == WIN32_ERROR(1300) {
                    // ERROR_NOT_ALL_ASSIGNED
                    log::error!("SeDebugPrivilege not granted - not running as administrator?");
                    return Err(PrivilegeError::PrivilegeNotHeld(
                        "SeDebugPrivilege".to_string(),
                    ));
                }

                log::error!(
                    "AdjustTokenPrivileges returned error: {} ({})",
                    last_error.0,
                    last_error.to_hresult()
                );

                return Err(PrivilegeError::AdjustPrivilegeFailed(
                    std::io::Error::from_raw_os_error(last_error.0 as i32),
                ));
            }

            log::info!("SeDebugPrivilege enabled successfully");
            Ok(())
        }
    }

    /// Checks if SeDebugPrivilege is currently enabled for the process.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if SeDebugPrivilege is enabled
    /// - `Ok(false)` if SeDebugPrivilege is not enabled
    /// - `Err` if the check fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use injector_core::PrivilegeManager;
    ///
    /// match PrivilegeManager::has_debug_privilege() {
    ///     Ok(true) => println!("SeDebugPrivilege is enabled"),
    ///     Ok(false) => println!("SeDebugPrivilege is not enabled"),
    ///     Err(e) => eprintln!("Failed to check: {}", e),
    /// }
    /// ```
    pub fn has_debug_privilege() -> Result<bool, PrivilegeError> {
        unsafe {
            // Open the process token
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(|e| {
                log::error!("Failed to open process token: {}", e);
                PrivilegeError::OpenTokenFailed(std::io::Error::last_os_error())
            })?;

            let _guard = TokenGuard(token);

            // Lookup the LUID for SeDebugPrivilege
            let mut luid = LUID::default();
            LookupPrivilegeValueW(None, windows::core::w!("SeDebugPrivilege"), &mut luid)
                .map_err(|e| {
                    log::error!("Failed to lookup privilege value: {}", e);
                    PrivilegeError::LookupPrivilegeFailed(std::io::Error::last_os_error())
                })?;

            // Get token privileges size
            let mut return_length = 0u32;
            let _ = GetTokenInformation(
                token,
                TokenPrivileges,
                None,
                0,
                &mut return_length,
            );

            let mut buffer = vec![0u8; return_length as usize];

            GetTokenInformation(
                token,
                TokenPrivileges,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                &mut return_length,
            )
            .map_err(|e| {
                log::error!("Failed to get token information: {}", e);
                PrivilegeError::OpenTokenFailed(std::io::Error::last_os_error())
            })?;

            // Parse the TOKEN_PRIVILEGES structure
            let privileges = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);

            // Check if SeDebugPrivilege is enabled
            // Note: TOKEN_PRIVILEGES is a variable-length structure, so we need to use pointer arithmetic
            let privileges_array = &privileges.Privileges as *const LUID_AND_ATTRIBUTES;
            for i in 0..privileges.PrivilegeCount {
                let priv_attr = &*privileges_array.offset(i as isize);
                if priv_attr.Luid.LowPart == luid.LowPart
                    && priv_attr.Luid.HighPart == luid.HighPart
                {
                    let enabled = (priv_attr.Attributes & SE_PRIVILEGE_ENABLED) != TOKEN_PRIVILEGES_ATTRIBUTES(0);
                    log::debug!("SeDebugPrivilege enabled: {}", enabled);
                    return Ok(enabled);
                }
            }

            log::debug!("SeDebugPrivilege not found in token");
            Ok(false)
        }
    }

    /// Attempts to enable SeDebugPrivilege with error logging.
    ///
    /// This is a convenience wrapper around `enable_debug_privilege()` that returns
    /// a boolean instead of a Result, and logs errors instead of returning them.
    ///
    /// # Returns
    ///
    /// - `true` if the privilege was successfully enabled
    /// - `false` if the privilege could not be enabled (with error logged)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use injector_core::PrivilegeManager;
    ///
    /// if PrivilegeManager::try_enable_debug_privilege() {
    ///     println!("Ready to inject into protected processes");
    /// } else {
    ///     println!("Limited to user-owned processes");
    /// }
    /// ```
    pub fn try_enable_debug_privilege() -> bool {
        match Self::enable_debug_privilege() {
            Ok(()) => {
                log::info!("SeDebugPrivilege enabled");
                true
            }
            Err(e) => {
                log::warn!("Failed to enable SeDebugPrivilege: {}", e);
                false
            }
        }
    }
}

/// RAII guard for automatic handle cleanup.
///
/// Ensures that Windows handles are properly closed when they go out of scope,
/// preventing handle leaks.
struct TokenGuard(HANDLE);

impl Drop for TokenGuard {
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
    fn test_is_administrator() {
        // This test should work regardless of admin status
        let result = PrivilegeManager::is_administrator();
        assert!(result.is_ok(), "Administrator check should not fail");

        let is_admin = result.unwrap();
        println!("Running as administrator: {}", is_admin);
    }

    #[test]
    fn test_enable_debug_privilege() {
        // This test will only succeed when running as administrator
        let result = PrivilegeManager::enable_debug_privilege();

        match result {
            Ok(()) => {
                println!("SeDebugPrivilege enabled successfully");
                // Verify it's actually enabled
                let has_priv = PrivilegeManager::has_debug_privilege();
                assert!(has_priv.is_ok());
                assert!(
                    has_priv.unwrap(),
                    "Privilege should be enabled after successful enable"
                );
            }
            Err(PrivilegeError::NotAdministrator) => {
                println!("Not running as administrator - this is expected");
            }
            Err(e) => {
                panic!("Unexpected error enabling privilege: {}", e);
            }
        }
    }

    #[test]
    fn test_has_debug_privilege() {
        // This test should work regardless of admin status
        let result = PrivilegeManager::has_debug_privilege();
        assert!(result.is_ok(), "Privilege check should not fail");

        let has_priv = result.unwrap();
        println!("Has SeDebugPrivilege: {}", has_priv);
    }
}

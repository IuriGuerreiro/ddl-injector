# Phase 5: Privilege Elevation

**Status:** ⏳ Pending
**Estimated Time:** 3-4 hours
**Complexity:** Medium

## Phase Overview

Implement SeDebugPrivilege elevation to allow injection into protected processes. This privilege is required to open processes owned by other users or system processes. This phase also adds administrator detection and displays privilege status in the UI.

## Objectives

- [ ] Implement privilege elevation functions
- [ ] Add SeDebugPrivilege acquisition
- [ ] Detect if running as administrator
- [ ] Handle UAC elevation gracefully
- [ ] Display privilege status in UI
- [ ] Add error handling for privilege failures
- [ ] Test with system processes

## Prerequisites

- ✅ Phase 4: UI foundation complete
- Understanding of Windows security model
- Knowledge of access tokens and privileges
- Administrator account (for testing)

## Learning Resources

- [Enabling and Disabling Privileges](https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--)
- [AdjustTokenPrivileges MSDN](https://docs.microsoft.com/en-us/windows/win32/api/secbaseapi/nf-secbaseapi-adjusttokenprivileges)
- [OpenProcessToken MSDN](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [SE_DEBUG_NAME Privilege](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)

## File Structure

```
injector-core/src/
├── privilege/
│   ├── mod.rs                  # Export privilege types
│   └── manager.rs              # Privilege management ← NEW
└── error.rs                    # Add PrivilegeError

injector-ui/src/
├── app.rs                      # Add privilege status ← UPDATE
└── ui/
    └── injection_panel.rs      # Show privilege status ← UPDATE
```

## Dependencies

Update `injector-core/Cargo.toml` to add security features:

```toml
[dependencies]
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_Threading",
    "Win32_System_Memory",
    "Win32_System_LibraryLoader",
    "Win32_Security",
    "Win32_System_SystemServices",  # ← Add this
] }
thiserror = "2.0"
log = "0.4"
```

## Step-by-Step Implementation

### Step 1: Add Privilege Error Types

**File:** `injector-core/src/error.rs` (add to existing)

```rust
/// Errors that can occur during privilege operations.
#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[error("Failed to open process token")]
    OpenTokenFailed(#[source] io::Error),

    #[error("Failed to lookup privilege value")]
    LookupPrivilegeFailed(#[source] io::Error),

    #[error("Failed to adjust token privileges")]
    AdjustPrivilegeFailed(#[source] io::Error),

    #[error("Privilege not held: {0}")]
    PrivilegeNotHeld(String),

    #[error("Not running as administrator")]
    NotAdministrator,
}
```

### Step 2: Implement Privilege Manager

**File:** `injector-core/src/privilege/manager.rs`

```rust
//! Windows privilege management.
//!
//! Provides utilities for checking and elevating process privileges,
//! particularly SeDebugPrivilege which is required for injecting into
//! protected processes.

use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;
use windows::core::PCWSTR;
use crate::error::PrivilegeError;

/// Manager for process privileges.
pub struct PrivilegeManager;

impl PrivilegeManager {
    /// Check if the current process is running as administrator.
    ///
    /// # Returns
    /// - `Ok(true)` if running as administrator
    /// - `Ok(false)` if not running as administrator
    /// - `Err` if unable to determine administrator status
    pub fn is_administrator() -> Result<bool, PrivilegeError> {
        unsafe {
            let mut is_admin = false;

            // Create SID for administrators group
            let mut sid_size = 0u32;
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                None,
                None,
                &mut sid_size,
            ).ok(); // Expected to fail with ERROR_INSUFFICIENT_BUFFER

            let mut admin_sid = vec![0u8; sid_size as usize];

            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                None,
                Some(admin_sid.as_mut_ptr() as *mut _),
                &mut sid_size,
            )
            .map_err(|_| PrivilegeError::OpenTokenFailed(
                std::io::Error::last_os_error()
            ))?;

            // Check if current user is member of administrators group
            CheckTokenMembership(
                None,
                PSID(admin_sid.as_ptr() as *mut _),
                &mut is_admin,
            )
            .map_err(|_| PrivilegeError::OpenTokenFailed(
                std::io::Error::last_os_error()
            ))?;

            Ok(is_admin.as_bool())
        }
    }

    /// Enable SeDebugPrivilege for the current process.
    ///
    /// This privilege allows opening processes owned by other users,
    /// including system processes. Requires administrator rights.
    ///
    /// # Errors
    /// Returns error if:
    /// - Not running as administrator
    /// - Unable to open process token
    /// - Privilege cannot be enabled
    pub fn enable_debug_privilege() -> Result<(), PrivilegeError> {
        log::debug!("Attempting to enable SeDebugPrivilege");

        unsafe {
            // Get current process token
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .map_err(|_| PrivilegeError::OpenTokenFailed(
                std::io::Error::last_os_error()
            ))?;

            // Ensure token is closed on scope exit
            let _token_guard = TokenGuard(token);

            // Lookup privilege LUID
            let mut luid = LUID::default();
            LookupPrivilegeValueW(
                PCWSTR::null(),
                windows::core::w!("SeDebugPrivilege"),
                &mut luid,
            )
            .map_err(|_| PrivilegeError::LookupPrivilegeFailed(
                std::io::Error::last_os_error()
            ))?;

            log::debug!("SeDebugPrivilege LUID: {:?}", luid);

            // Set up privilege structure
            let mut privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            // Adjust token privileges
            AdjustTokenPrivileges(
                token,
                false,
                Some(&mut privileges),
                0,
                None,
                None,
            )
            .map_err(|_| PrivilegeError::AdjustPrivilegeFailed(
                std::io::Error::last_os_error()
            ))?;

            // Check if privilege was actually granted
            let last_error = std::io::Error::last_os_error();
            if last_error.raw_os_error() == Some(1300) {
                // ERROR_NOT_ALL_ASSIGNED
                log::error!("SeDebugPrivilege not granted - not running as administrator?");
                return Err(PrivilegeError::NotAdministrator);
            }

            log::info!("SeDebugPrivilege enabled successfully");
            Ok(())
        }
    }

    /// Check if SeDebugPrivilege is enabled.
    pub fn has_debug_privilege() -> Result<bool, PrivilegeError> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            )
            .map_err(|_| PrivilegeError::OpenTokenFailed(
                std::io::Error::last_os_error()
            ))?;

            let _token_guard = TokenGuard(token);

            // Lookup privilege LUID
            let mut luid = LUID::default();
            LookupPrivilegeValueW(
                PCWSTR::null(),
                windows::core::w!("SeDebugPrivilege"),
                &mut luid,
            )
            .map_err(|_| PrivilegeError::LookupPrivilegeFailed(
                std::io::Error::last_os_error()
            ))?;

            // Get token privileges
            let mut return_length = 0;
            GetTokenInformation(
                token,
                TokenPrivileges,
                None,
                0,
                &mut return_length,
            ).ok(); // Expected to fail

            let mut buffer = vec![0u8; return_length as usize];
            GetTokenInformation(
                token,
                TokenPrivileges,
                Some(buffer.as_mut_ptr() as *mut _),
                return_length,
                &mut return_length,
            )
            .map_err(|_| PrivilegeError::OpenTokenFailed(
                std::io::Error::last_os_error()
            ))?;

            let privileges = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);

            // Check if SeDebugPrivilege is enabled
            for i in 0..privileges.PrivilegeCount {
                let priv_attr = &privileges.Privileges[i as usize];
                if priv_attr.Luid.LowPart == luid.LowPart
                    && priv_attr.Luid.HighPart == luid.HighPart
                {
                    return Ok((priv_attr.Attributes & SE_PRIVILEGE_ENABLED) != 0);
                }
            }

            Ok(false)
        }
    }

    /// Try to enable SeDebugPrivilege, returning whether it succeeded.
    ///
    /// This is a convenience method that logs errors but doesn't fail.
    pub fn try_enable_debug_privilege() -> bool {
        match Self::enable_debug_privilege() {
            Ok(_) => {
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

/// RAII guard for closing token handle.
struct TokenGuard(HANDLE);

impl Drop for TokenGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_administrator() {
        // This test may pass or fail depending on how tests are run
        let result = PrivilegeManager::is_administrator();
        assert!(result.is_ok());
        println!("Running as administrator: {}", result.unwrap());
    }

    #[test]
    fn test_enable_debug_privilege() {
        // This test requires administrator privileges
        let result = PrivilegeManager::enable_debug_privilege();

        if result.is_err() {
            println!("Note: This test requires administrator privileges");
        }

        // Should either succeed or fail with NotAdministrator
        match result {
            Ok(_) => println!("SeDebugPrivilege enabled"),
            Err(PrivilegeError::NotAdministrator) => println!("Not running as admin"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_has_debug_privilege() {
        let _ = PrivilegeManager::enable_debug_privilege();
        let result = PrivilegeManager::has_debug_privilege();
        assert!(result.is_ok());
    }
}
```

### Step 3: Update Privilege Module

**File:** `injector-core/src/privilege/mod.rs`

```rust
//! Windows privilege management.

mod manager;

pub use manager::PrivilegeManager;
```

### Step 4: Update Library Exports

**File:** `injector-core/src/lib.rs`

```rust
//! Core DLL injection library for Windows.

pub mod error;
pub mod process;
pub mod injection;
pub mod memory;
pub mod pe;
pub mod privilege;

// Re-export commonly used types
pub use error::{InjectionError, ProcessError, PrivilegeError};
pub use process::{ProcessEnumerator, ProcessHandle, ProcessInfo};
pub use injection::{InjectionMethod, CreateRemoteThreadInjector};
pub use privilege::PrivilegeManager;
```

### Step 5: Update UI to Show Privilege Status

**File:** `injector-ui/src/app.rs` (update)

Add to `InjectorApp` struct:

```rust
/// Privilege status
has_debug_privilege: bool,
is_administrator: bool,
```

In `new()` method:

```rust
// Check privilege status
let is_administrator = PrivilegeManager::is_administrator().unwrap_or(false);
let has_debug_privilege = if is_administrator {
    PrivilegeManager::try_enable_debug_privilege()
} else {
    false
};

log::info!("Administrator: {}, SeDebugPrivilege: {}", is_administrator, has_debug_privilege);
```

### Step 6: Update Injection Panel to Display Status

**File:** `injector-ui/src/ui/injection_panel.rs` (update render function signature)

Add parameters:

```rust
pub fn render(
    // ... existing parameters ...
    is_administrator: bool,
    has_debug_privilege: bool,
)
```

Add privilege status display:

```rust
// Privilege status
ui.group(|ui| {
    ui.label("Privilege Status:");

    ui.horizontal(|ui| {
        if is_administrator {
            ui.colored_label(egui::Color32::GREEN, "✓ Administrator");
        } else {
            ui.colored_label(egui::Color32::RED, "✗ Not Administrator");
        }
    });

    ui.horizontal(|ui| {
        if has_debug_privilege {
            ui.colored_label(egui::Color32::GREEN, "✓ SeDebugPrivilege");
        } else {
            ui.colored_label(egui::Color32::YELLOW, "⚠ SeDebugPrivilege not enabled");
        }
    });

    if !is_administrator {
        ui.add_space(5.0);
        ui.small("Run as administrator to inject into protected processes");
    }
});
```

### Step 7: Add UAC Manifest (Optional)

Create `injector-ui/injector.exe.manifest`:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="*"
    name="DLL Injector"
    type="win32"
  />
  <description>DLL Injection Tool</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
```

To embed manifest, add build script `injector-ui/build.rs`:

```rust
fn main() {
    if cfg!(target_os = "windows") {
        embed_resource::compile("injector.rc");
    }
}
```

And `injector-ui/injector.rc`:

```
1 RT_MANIFEST "injector.exe.manifest"
```

Add build dependency in `injector-ui/Cargo.toml`:

```toml
[build-dependencies]
embed-resource = "2.4"
```

## Testing Checklist

- [ ] Code compiles without errors
- [ ] Can detect administrator status
- [ ] SeDebugPrivilege enables when running as admin
- [ ] UI shows correct privilege status
- [ ] Can inject into system processes (with admin)
- [ ] Gracefully handles non-admin scenario
- [ ] Tests pass (with and without admin)

## Common Pitfalls

### 1. ERROR_NOT_ALL_ASSIGNED
**Problem:** AdjustTokenPrivileges succeeds but privilege not granted
**Solution:** Check GetLastError() after AdjustTokenPrivileges

### 2. Token Handle Leak
**Problem:** Forgetting to close token handle
**Solution:** Use RAII TokenGuard

### 3. UAC Manifest Not Applied
**Problem:** Manifest doesn't trigger UAC prompt
**Solution:** Ensure manifest is embedded via build script

### 4. Privilege Check Timing
**Problem:** Checking privilege before enabling it
**Solution:** Enable first, then check status

## Completion Criteria

Phase 5 is complete when:
- ✅ Can detect administrator status
- ✅ Can enable SeDebugPrivilege
- ✅ Can check if privilege is enabled
- ✅ UI displays privilege status
- ✅ Can inject into system processes (with admin)
- ✅ All tests pass
- ✅ Graceful degradation without admin

## Git Commit

```bash
git add injector-core/src/privilege/ injector-ui/src/
git commit -m "feat: implement privilege elevation with SeDebugPrivilege

- Add PrivilegeManager for Windows privilege operations
- Implement administrator detection
- Enable SeDebugPrivilege for system process access
- Add privilege status checking
- Display privilege status in UI
- Include RAII token handle management
- Add comprehensive error handling

Can now inject into protected processes when running as administrator.

Follows docs/phases/phase-05-privileges.md
"
```

## Next Steps

Proceed to **Phase 6: Manual Mapping** (docs/phases/phase-06-manual-mapping.md)

Phase 6 will implement:
- PE file parsing
- Manual section mapping
- Import resolution
- Base relocation handling
- Stealthy DLL loading

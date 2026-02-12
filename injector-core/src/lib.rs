// Core library for DLL injection functionality

pub mod error;
pub mod process;
pub mod injection;
pub mod memory;
pub mod pe;
pub mod privilege;

pub use error::{InjectionError, ProcessError, PrivilegeError};
pub use process::{ProcessEnumerator, ProcessHandle, ProcessInfo};
pub use injection::{InjectionMethod, CreateRemoteThreadInjector, ManualMapInjector};
pub use privilege::PrivilegeManager;

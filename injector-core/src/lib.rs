// Core library for DLL injection functionality

pub mod error;
pub mod injection;
pub mod memory;
pub mod native;
pub mod pe;
pub mod privilege;
pub mod process;
pub mod shellcode;

pub use error::{InjectionError, PrivilegeError, ProcessError};
pub use injection::{
    CreateRemoteThreadInjector, EarlyBirdApcInjector, InjectionMethod, ManualMapInjector,
    NtCreateThreadExInjector, QueueUserApcInjector, ReflectiveLoaderInjector,
    SectionMappingInjector, ThreadHijackingInjector,
};
pub use privilege::PrivilegeManager;
pub use process::{ProcessEnumerator, ProcessHandle, ProcessInfo};

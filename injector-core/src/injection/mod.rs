//! DLL injection methods and utilities.

pub mod traits;
pub mod create_remote_thread;
pub mod manual_map;
pub mod queue_user_apc;
pub mod nt_create_thread;

pub use traits::{
    InjectionMethod,
    InjectionResult,
    validate_dll_path,
    validate_architecture,
    is_process_64bit,
};
pub use create_remote_thread::CreateRemoteThreadInjector;
pub use manual_map::ManualMapInjector;
pub use queue_user_apc::QueueUserApcInjector;
pub use nt_create_thread::NtCreateThreadExInjector;

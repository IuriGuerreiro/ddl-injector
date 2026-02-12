//! DLL injection methods and utilities.

pub mod create_remote_thread;
pub mod manual_map;
pub mod nt_create_thread;
pub mod queue_user_apc;
pub mod traits;

pub use create_remote_thread::CreateRemoteThreadInjector;
pub use manual_map::ManualMapInjector;
pub use nt_create_thread::NtCreateThreadExInjector;
pub use queue_user_apc::QueueUserApcInjector;
pub use traits::{
    is_process_64bit, validate_architecture, validate_dll_path, InjectionMethod, InjectionResult,
};

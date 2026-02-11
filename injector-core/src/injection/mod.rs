//! DLL injection methods and utilities.

pub mod traits;
pub mod create_remote_thread;
mod manual_map;
mod queue_user_apc;
mod nt_create_thread;

pub use traits::{
    InjectionMethod,
    InjectionResult,
    validate_dll_path,
    validate_architecture,
    is_process_64bit,
};
pub use create_remote_thread::CreateRemoteThreadInjector;

//! DLL injection methods and utilities.

pub mod create_remote_thread;
pub mod dll_proxy;
pub mod early_bird_apc;
pub mod manual_map;
pub mod nt_create_thread;
pub mod proxy_generator;
pub mod queue_user_apc;
pub mod reflective_loader;
pub mod section_mapping;
pub mod thread_hijacking;
pub mod traits;

pub use create_remote_thread::CreateRemoteThreadInjector;
pub use dll_proxy::DllProxyInjector;
pub use early_bird_apc::EarlyBirdApcInjector;
pub use manual_map::ManualMapInjector;
pub use nt_create_thread::NtCreateThreadExInjector;
pub use proxy_generator::ProxyDllGenerator;
pub use queue_user_apc::QueueUserApcInjector;
pub use reflective_loader::ReflectiveLoaderInjector;
pub use section_mapping::SectionMappingInjector;
pub use thread_hijacking::ThreadHijackingInjector;
pub use traits::{
    is_process_64bit, validate_architecture, validate_dll_path, InjectionMethod, InjectionResult,
    PreparationMethod, PreparationOptions, PreparationResult,
};

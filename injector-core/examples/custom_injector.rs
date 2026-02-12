//! Custom Injector Example
//!
//! Demonstrates advanced usage with all 4 injection methods.
//! Shows how to select injection method at runtime and compare techniques.
//!
//! Usage:
//!   cargo run --example custom_injector -- <method> <process_name> <dll_path>
//!
//! Methods:
//!   crt    - CreateRemoteThread (most compatible)
//!   apc    - QueueUserAPC (stealthier, requires alertable thread)
//!   nt     - NtCreateThreadEx (kernel-level, more reliable)
//!   manual - Manual Map (no LoadLibrary, advanced)
//!
//! Example:
//!   cargo run --example custom_injector -- crt notepad.exe C:\path\to\test_dll.dll
//!   cargo run --example custom_injector -- manual calc.exe C:\path\to\test_dll.dll

use injector_core::{
    CreateRemoteThreadInjector, InjectionMethod, ManualMapInjector, NtCreateThreadExInjector,
    PrivilegeManager, ProcessEnumerator, ProcessHandle, QueueUserApcInjector,
};
use std::env;
use std::path::PathBuf;
use windows::Win32::System::Threading::{
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let method_name = &args[1];
    let process_name = &args[2];
    let dll_path = PathBuf::from(&args[3]);

    println!("DLL Injector - Custom Example");
    println!("==============================");
    println!();

    if let Err(e) = inject(method_name, process_name, &dll_path) {
        eprintln!("❌ Error: {}", e);
        std::process::exit(1);
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} <method> <process_name> <dll_path>", program);
    eprintln!();
    eprintln!("Methods:");
    eprintln!("  crt    - CreateRemoteThread (most compatible, well-known)");
    eprintln!("  apc    - QueueUserAPC (stealthier, requires alertable thread)");
    eprintln!("  nt     - NtCreateThreadEx (uses native API, more reliable)");
    eprintln!("  manual - Manual Map (no LoadLibrary, bypasses module list)");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  {} crt notepad.exe C:\\\\path\\\\to\\\\test_dll.dll", program);
}

fn inject(
    method_name: &str,
    process_name: &str,
    dll_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Select injection method based on user input
    let injector: Box<dyn InjectionMethod> = match method_name.to_lowercase().as_str() {
        "crt" => {
            println!("Using: CreateRemoteThread");
            println!("  Pros: Most compatible, works on all Windows versions");
            println!("  Cons: Well-known, easily detected by anti-cheat");
            println!();
            Box::new(CreateRemoteThreadInjector)
        }
        "apc" => {
            println!("Using: QueueUserAPC");
            println!("  Pros: Stealthier than CreateRemoteThread");
            println!("  Cons: Requires target process to have alertable thread");
            println!();
            Box::new(QueueUserApcInjector)
        }
        "nt" => {
            println!("Using: NtCreateThreadEx");
            println!("  Pros: Uses undocumented native API, more reliable");
            println!("  Cons: May fail on some Windows versions, requires ntdll.dll");
            println!();
            Box::new(NtCreateThreadExInjector)
        }
        "manual" => {
            println!("Using: Manual Map");
            println!("  Pros: Doesn't use LoadLibrary, bypasses module list");
            println!("  Cons: Most complex, doesn't support all DLLs (TLS, delays)");
            println!();
            Box::new(ManualMapInjector)
        }
        _ => {
            return Err(format!(
                "Unknown method '{}'. Use: crt, apc, nt, or manual",
                method_name
            )
            .into())
        }
    };

    // Elevate privileges
    println!("[1/5] Enabling Debug privilege...");
    PrivilegeManager::enable_debug_privilege()?;
    println!("    ✓ Privilege enabled");

    // Find target process
    println!("[2/5] Finding process '{}'...", process_name);
    let processes = ProcessEnumerator::find_by_name(process_name)?;

    if processes.is_empty() {
        return Err(format!("Process '{}' not found", process_name).into());
    }

    let target = &processes[0];
    println!("    ✓ Found: {} (PID: {})", target.name, target.pid);

    // Open process handle
    println!("[3/5] Opening process handle...");
    let access_rights = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;

    let handle = ProcessHandle::open(target.pid, access_rights)?;
    println!("    ✓ Handle opened (PID: {})", handle.pid());

    // Validate DLL
    println!("[4/5] Validating DLL...");
    if !dll_path.is_absolute() {
        return Err("DLL path must be absolute".into());
    }
    if !dll_path.exists() {
        return Err(format!("DLL not found: {}", dll_path.display()).into());
    }
    println!("    ✓ DLL: {}", dll_path.display());

    // Inject using selected method
    println!("[5/5] Injecting DLL using {}...", injector.name());
    injector.inject(&handle, dll_path)?;
    println!("    ✓ Injection successful!");

    println!();
    println!("✅ Complete! DLL injected using {} method", injector.name());

    Ok(())
}

//! Basic DLL Injection Example
//!
//! Demonstrates simple DLL injection using CreateRemoteThread method.
//! This is the easiest and most compatible injection technique.
//!
//! Usage:
//!   cargo run --example basic_injection -- <process_name> <dll_path>
//!
//! Example:
//!   cargo run --example basic_injection -- notepad.exe C:\path\to\test_dll.dll

use injector_core::{
    CreateRemoteThreadInjector, InjectionMethod, PrivilegeManager, ProcessEnumerator,
    ProcessHandle,
};
use std::env;
use std::path::PathBuf;
use windows::Win32::System::Threading::{
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

fn main() {
    // Initialize logger for debugging (optional but helpful)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <process_name> <dll_path>", args[0]);
        eprintln!("Example: {} notepad.exe C:\\\\path\\\\to\\\\test_dll.dll", args[0]);
        std::process::exit(1);
    }

    let process_name = &args[1];
    let dll_path = PathBuf::from(&args[2]);

    println!("DLL Injector - Basic Example");
    println!("=============================");
    println!("Target Process: {}", process_name);
    println!("DLL Path: {}", dll_path.display());
    println!();

    // Run the injection
    if let Err(e) = inject(process_name, &dll_path) {
        eprintln!("❌ Injection failed: {}", e);
        std::process::exit(1);
    }

    println!("✅ Injection completed successfully!");
}

fn inject(process_name: &str, dll_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Elevate to Debug privileges (required for opening most processes)
    println!("[1/5] Elevating to Debug privileges...");
    PrivilegeManager::enable_debug_privilege()
        .map_err(|e| format!("Failed to enable debug privilege: {}", e))?;
    println!("    ✓ Debug privilege enabled");

    // Step 2: Find the target process by name
    println!("[2/5] Searching for process '{}'...", process_name);
    let processes = ProcessEnumerator::find_by_name(process_name)
        .map_err(|e| format!("Failed to enumerate processes: {}", e))?;

    if processes.is_empty() {
        return Err(format!("Process '{}' not found. Is it running?", process_name).into());
    }

    // If multiple processes found, use the first one
    let target_process = &processes[0];
    println!("    ✓ Found process: {} (PID: {})", target_process.name, target_process.pid);

    if processes.len() > 1 {
        println!("    ⚠ Note: Multiple instances found. Using PID {}", target_process.pid);
        for (i, p) in processes.iter().enumerate().skip(1) {
            println!("           Other instance {}: PID {}", i, p.pid);
        }
    }

    // Step 3: Open a handle to the target process with required permissions
    println!("[3/5] Opening handle to process...");
    let access_rights = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;

    let handle = ProcessHandle::open(target_process.pid, access_rights)
        .map_err(|e| format!("Failed to open process: {}. Run as administrator?", e))?;
    println!("    ✓ Process handle opened successfully");

    // Step 4: Validate DLL path
    println!("[4/5] Validating DLL path...");
    if !dll_path.is_absolute() {
        return Err("DLL path must be absolute. Use full path (e.g., C:\\path\\to\\dll.dll)".into());
    }
    if !dll_path.exists() {
        return Err(format!("DLL file not found: {}", dll_path.display()).into());
    }
    println!("    ✓ DLL path validated: {}", dll_path.display());

    // Step 5: Perform injection using CreateRemoteThread
    println!("[5/5] Injecting DLL using CreateRemoteThread method...");
    let injector = CreateRemoteThreadInjector;
    injector
        .inject(&handle, dll_path)
        .map_err(|e| format!("Injection failed: {}", e))?;
    println!("    ✓ DLL injected successfully!");

    Ok(())
}

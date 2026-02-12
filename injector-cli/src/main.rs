//! Simple CLI tool for testing DLL injection.

use injector_core::*;
use std::env;
use std::path::PathBuf;

fn main() {
    // Initialize logger
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <process_name_or_pid> <dll_path>", args[0]);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} notepad.exe C:\\path\\to\\test.dll", args[0]);
        eprintln!("  {} 1234 C:\\path\\to\\test.dll", args[0]);
        std::process::exit(1);
    }

    let process_identifier = &args[1];
    let dll_path = PathBuf::from(&args[2]);

    // Convert DLL path to absolute if needed
    let dll_path = if dll_path.is_absolute() {
        dll_path
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(dll_path)
    };

    println!("🔍 Searching for process: {}", process_identifier);

    // Try to parse as PID first, otherwise treat as process name
    let processes = if let Ok(pid) = process_identifier.parse::<u32>() {
        println!("   Looking for PID: {}", pid);
        match ProcessEnumerator::find_by_pid(pid) {
            Ok(info) => vec![info],
            Err(e) => {
                eprintln!("❌ Failed to find process: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("   Looking for process name: {}", process_identifier);
        match ProcessEnumerator::find_by_name(process_identifier) {
            Ok(procs) => {
                if procs.is_empty() {
                    eprintln!("❌ No processes found with name: {}", process_identifier);
                    std::process::exit(1);
                }
                procs
            }
            Err(e) => {
                eprintln!("❌ Failed to enumerate processes: {}", e);
                std::process::exit(1);
            }
        }
    };

    if processes.len() > 1 {
        println!("⚠️  Found {} processes with that name:", processes.len());
        for (i, proc) in processes.iter().enumerate() {
            let path_str = proc.path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<unknown>".to_string());
            println!("   {}. PID {} - {}", i + 1, proc.pid, path_str);
        }
        println!("   Using the first one (PID {})", processes[0].pid);
    }

    let target = &processes[0];
    println!("✓ Found process: {} (PID {})", target.name, target.pid);
    if let Some(ref path) = target.path {
        println!("   Path: {}", path.display());
    }

    // Create injector
    let injector = CreateRemoteThreadInjector::new();
    println!("\n💉 Using injection method: {}", injector.name());
    println!("   DLL path: {}", dll_path.display());

    // Check if DLL exists
    if !dll_path.exists() {
        eprintln!("\n❌ DLL file not found: {}", dll_path.display());
        std::process::exit(1);
    }

    // Open process handle
    println!("\n🔓 Opening process handle...");
    let handle = match ProcessHandle::open(target.pid, injector.required_access()) {
        Ok(h) => {
            println!("✓ Process handle opened successfully");
            h
        }
        Err(e) => {
            eprintln!("❌ Failed to open process: {}", e);
            eprintln!("\n💡 Tip: You may need to run as Administrator for some processes");
            std::process::exit(1);
        }
    };

    // Perform injection
    println!("\n💉 Injecting DLL...");
    match injector.inject(&handle, &dll_path) {
        Ok(()) => {
            println!("\n✅ Injection successful!");
            println!("   The DLL should now be loaded in the target process");
        }
        Err(e) => {
            eprintln!("\n❌ Injection failed: {}", e);
            std::process::exit(1);
        }
    }
}

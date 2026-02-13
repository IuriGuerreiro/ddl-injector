//! CLI tool for DLL injection with multiple injection methods.

use clap::Parser;
use injector_core::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "injector-cli")]
#[command(about = "DLL injection tool with multiple injection methods", long_about = None)]
struct Args {
    /// Target process name or PID (not used for dll-proxy method)
    #[arg(value_name = "PROCESS")]
    process: Option<String>,

    /// Path to the DLL file to inject (payload for dll-proxy)
    #[arg(value_name = "DLL_PATH")]
    dll_path: Option<PathBuf>,

    /// Injection method to use
    #[arg(
        short,
        long,
        value_name = "METHOD",
        default_value = "create-remote-thread"
    )]
    method: InjectionMethodType,

    /// [DLL Proxy] Path to target executable
    #[arg(long, value_name = "EXE_PATH")]
    target_exe: Option<PathBuf>,

    /// [DLL Proxy] System DLL to proxy (e.g., "version.dll")
    #[arg(long, value_name = "DLL_NAME")]
    system_dll: Option<String>,

    /// [DLL Proxy] Backup original DLL before replacing
    #[arg(long)]
    backup: bool,

    /// [DLL Proxy] Cleanup mode: restore backups
    #[arg(long)]
    cleanup: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum InjectionMethodType {
    /// CreateRemoteThread injection (classic method)
    #[value(name = "create-remote-thread")]
    CreateRemoteThread,

    /// Manual mapping injection (stealth method)
    #[value(name = "manual-map")]
    ManualMap,

    /// QueueUserAPC injection (APC-based method)
    #[value(name = "queue-user-apc")]
    QueueUserApc,

    /// NtCreateThreadEx injection (native API method)
    #[value(name = "nt-create-thread-ex")]
    NtCreateThreadEx,

    /// Section Mapping injection (memory-efficient method) - STABLE
    #[value(name = "section-mapping")]
    SectionMapping,

    /// Thread Hijacking injection (thread context manipulation) - EXPERIMENTAL
    #[value(name = "thread-hijacking")]
    ThreadHijacking,

    /// Reflective Loader injection (PIC loader, no LoadLibrary) - RESEARCH
    #[value(name = "reflective-loader")]
    ReflectiveLoader,

    /// DLL Proxy/Hijacking (file-based, loads before anti-cheat) - STEALTH
    #[value(name = "dll-proxy")]
    DllProxy,
}

fn main() {
    // Initialize logger
    env_logger::init();

    // Parse arguments
    let args = Args::parse();

    // Handle DLL Proxy method differently (preparation-based, not runtime)
    if matches!(args.method, InjectionMethodType::DllProxy) {
        handle_dll_proxy(&args);
        return;
    }

    // For runtime injection methods, require process and DLL path
    let process = args.process.as_ref().expect("PROCESS argument required for runtime injection methods");
    let dll_path = args.dll_path.as_ref().expect("DLL_PATH argument required for runtime injection methods");

    // Convert DLL path to absolute if needed
    let dll_path = if dll_path.is_absolute() {
        dll_path.clone()
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(dll_path)
    };

    println!("🔍 Searching for process: {}", process);

    // Try to parse as PID first, otherwise treat as process name
    let processes = if let Ok(pid) = process.parse::<u32>() {
        println!("   Looking for PID: {}", pid);
        match ProcessEnumerator::find_by_pid(pid) {
            Ok(info) => vec![info],
            Err(e) => {
                eprintln!("❌ Failed to find process: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("   Looking for process name: {}", process);
        match ProcessEnumerator::find_by_name(process) {
            Ok(procs) => {
                if procs.is_empty() {
                    eprintln!("❌ No processes found with name: {}", process);
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
            let path_str = proc
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            println!("   {}. PID {} - {}", i + 1, proc.pid, path_str);
        }
        println!("   Using the first one (PID {})", processes[0].pid);
    }

    let target = &processes[0];
    println!("✓ Found process: {} (PID {})", target.name, target.pid);
    if let Some(ref path) = target.path {
        println!("   Path: {}", path.display());
    }

    // Helper function to perform injection with common logic
    fn perform_injection<I: InjectionMethod>(
        injector: I,
        target_pid: u32,
        dll_path: &std::path::Path,
        extra_info: Option<&str>,
    ) -> Result<(), InjectionError> {
        println!("\n💉 Using injection method: {}", injector.name());
        println!("   DLL path: {}", dll_path.display());
        if let Some(info) = extra_info {
            println!("   {}", info);
        }

        // Check if DLL exists
        if !dll_path.exists() {
            eprintln!("\n❌ DLL file not found: {}", dll_path.display());
            std::process::exit(1);
        }

        // Open process handle
        println!("\n🔓 Opening process handle...");
        let handle = match ProcessHandle::open(target_pid, injector.required_access()) {
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
        injector.inject(&handle, dll_path)
    }

    // Create the appropriate injector based on method
    let result = match args.method {
        InjectionMethodType::CreateRemoteThread => {
            perform_injection(CreateRemoteThreadInjector::new(), target.pid, &dll_path, None)
        }
        InjectionMethodType::ManualMap => {
            perform_injection(
                ManualMapInjector,
                target.pid,
                &dll_path,
                Some("⚠️  Advanced stealth injection - DLL will not appear in PEB module list"),
            )
        }
        InjectionMethodType::QueueUserApc => {
            perform_injection(QueueUserApcInjector::new(), target.pid, &dll_path, None)
        }
        InjectionMethodType::NtCreateThreadEx => {
            perform_injection(NtCreateThreadExInjector::new(), target.pid, &dll_path, None)
        }
        InjectionMethodType::SectionMapping => {
            perform_injection(
                SectionMappingInjector::new(),
                target.pid,
                &dll_path,
                Some("✨ STABLE - Memory-efficient section-based injection"),
            )
        }
        InjectionMethodType::ThreadHijacking => {
            perform_injection(
                ThreadHijackingInjector::new(),
                target.pid,
                &dll_path,
                Some("⚠️  EXPERIMENTAL - Hijacks existing thread (higher crash risk)"),
            )
        }
        InjectionMethodType::ReflectiveLoader => {
            perform_injection(
                ReflectiveLoaderInjector::new(),
                target.pid,
                &dll_path,
                Some("🔬 RESEARCH - Advanced PIC loader (not fully implemented)"),
            )
        }
        InjectionMethodType::DllProxy => {
            unreachable!("DLL Proxy is handled separately")
        }
    };

    match result {
        Ok(()) => {
            println!("\n✅ Injection successful!");
            println!("   The DLL should now be loaded in the target process");
            if matches!(args.method, InjectionMethodType::ManualMap) {
                println!("\n💡 Stealth Note:");
                println!("   - DLL will NOT appear in Process Explorer's module list");
                println!("   - DLL will NOT appear in Windows loader structures (PEB)");
                println!("   - Detection requires advanced memory scanning");
            }
        }
        Err(e) => {
            eprintln!("\n❌ Injection failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Handle DLL Proxy injection (preparation-based method).
fn handle_dll_proxy(args: &Args) {
    println!("🔧 DLL Proxy/Hijacking Mode");
    println!("   This is a file-based injection method that doesn't require a running process.");
    println!();

    let injector = DllProxyInjector::new();

    // Handle cleanup mode
    if args.cleanup {
        let target_exe = args.target_exe.as_ref().expect("--target-exe required for cleanup");

        println!("🧹 Cleaning up DLL proxy injection...");
        println!("   Target: {}", target_exe.display());

        match injector.cleanup(target_exe) {
            Ok(()) => {
                println!("\n✅ Cleanup successful!");
                println!("   Backups have been restored.");
            }
            Err(e) => {
                eprintln!("\n❌ Cleanup failed: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Normal preparation mode
    let target_exe = args.target_exe.as_ref().expect("--target-exe required for DLL proxy method");
    let payload_dll = args.dll_path.as_ref().expect("DLL_PATH required for DLL proxy method");
    let system_dll = args.system_dll.as_ref().expect("--system-dll required for DLL proxy method");

    // Convert paths to absolute
    let target_exe = if target_exe.is_absolute() {
        target_exe.clone()
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(target_exe)
    };

    let payload_dll = if payload_dll.is_absolute() {
        payload_dll.clone()
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(payload_dll)
    };

    println!("📋 Configuration:");
    println!("   Target executable: {}", target_exe.display());
    println!("   Payload DLL: {}", payload_dll.display());
    println!("   System DLL to proxy: {}", system_dll);
    println!("   Backup original: {}", if args.backup { "Yes" } else { "No" });
    println!();

    // Validate files exist
    if !target_exe.exists() {
        eprintln!("❌ Target executable not found: {}", target_exe.display());
        std::process::exit(1);
    }

    if !payload_dll.exists() {
        eprintln!("❌ Payload DLL not found: {}", payload_dll.display());
        std::process::exit(1);
    }

    // Create preparation options
    let options = PreparationOptions::new(system_dll.clone())
        .with_backup(args.backup);

    // Prepare the injection
    println!("🔨 Generating proxy DLL...");
    println!("   This may take a moment (compiling Rust code)...");
    println!();

    match injector.prepare(&target_exe, &payload_dll, &options) {
        Ok(result) => {
            println!("\n{}", result.instructions);
        }
        Err(e) => {
            eprintln!("\n❌ Preparation failed: {}", e);
            eprintln!();
            eprintln!("💡 Troubleshooting tips:");
            eprintln!("   - Ensure Rust toolchain is installed (cargo must be in PATH)");
            eprintln!("   - Check that the system DLL name is correct (e.g., 'version.dll')");
            eprintln!("   - Verify you have write permissions to the target directory");
            eprintln!("   - Make sure the target application is not running");
            std::process::exit(1);
        }
    }
}

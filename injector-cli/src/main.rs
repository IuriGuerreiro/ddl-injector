//! CLI tool for DLL injection with multiple injection methods.

use clap::Parser;
use injector_core::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "injector-cli")]
#[command(about = "DLL injection tool with multiple injection methods", long_about = None)]
struct Args {
    /// Target process name or PID
    #[arg(value_name = "PROCESS")]
    process: String,

    /// Path to the DLL file to inject
    #[arg(value_name = "DLL_PATH")]
    dll_path: PathBuf,

    /// Injection method to use
    #[arg(
        short,
        long,
        value_name = "METHOD",
        default_value = "create-remote-thread"
    )]
    method: InjectionMethodType,
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
}

fn main() {
    // Initialize logger
    env_logger::init();

    // Parse arguments
    let args = Args::parse();

    // Convert DLL path to absolute if needed
    let dll_path = if args.dll_path.is_absolute() {
        args.dll_path
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(args.dll_path)
    };

    println!("🔍 Searching for process: {}", args.process);

    // Try to parse as PID first, otherwise treat as process name
    let processes = if let Ok(pid) = args.process.parse::<u32>() {
        println!("   Looking for PID: {}", pid);
        match ProcessEnumerator::find_by_pid(pid) {
            Ok(info) => vec![info],
            Err(e) => {
                eprintln!("❌ Failed to find process: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("   Looking for process name: {}", args.process);
        match ProcessEnumerator::find_by_name(&args.process) {
            Ok(procs) => {
                if procs.is_empty() {
                    eprintln!("❌ No processes found with name: {}", args.process);
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

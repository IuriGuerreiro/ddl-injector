# DLL Injector

A multi-method DLL injector built in Rust with a modern graphical user interface.

## Features

- **Multiple Injection Methods**:
  - CreateRemoteThread - Classic injection method
  - Manual Mapping - Advanced stealth injection
  - QueueUserAPC - Thread hijacking technique
  - NtCreateThreadEx - Native API injection

- **Modern UI**: Built with egui for a responsive and intuitive interface
- **Safe and Reliable**: Leverages Rust's memory safety guarantees
- **Cross-architecture**: Supports both x86 and x64 processes

## Project Status

- ✅ Phase 1: Project Foundation - Complete
- ⏳ Phase 2: Process Enumeration - Planned
- ⏳ Phase 3: Basic Injection (CreateRemoteThread) - Planned
- ⏳ Phase 4: UI Foundation - Planned
- ⏳ Phase 5: QueueUserAPC Method - Planned
- ⏳ Phase 6: Manual Mapping - Planned
- ⏳ Phase 7: NtCreateThreadEx Method - Planned
- ⏳ Phase 8: Configuration & Polish - Planned

## Building

Build the project in release mode:

```bash
cargo build --release
```

The compiled binary will be located at `target/release/injector.exe`.

## Running

Run the UI application:

```bash
cargo run --release -p injector-ui
```

Or run the compiled binary directly:

```bash
./target/release/injector.exe
```

## Project Structure

```
dllInjector/
├── injector-core/       # Core injection library
│   ├── src/
│   │   ├── error.rs     # Error types
│   │   ├── process/     # Process enumeration and management
│   │   ├── injection/   # Injection method implementations
│   │   ├── memory/      # Memory operations
│   │   ├── pe/          # PE file parsing
│   │   └── privilege/   # Privilege management
│   └── Cargo.toml
├── injector-ui/         # GUI application
│   ├── src/
│   │   ├── main.rs      # Application entry point
│   │   ├── app.rs       # Main application logic
│   │   ├── config.rs    # Configuration management
│   │   └── ui/          # UI components
│   └── Cargo.toml
└── docs/                # Documentation
    ├── architecture.md
    └── phases/          # Phase-by-phase implementation plans
```

## Legal Disclaimer

This tool is provided for educational and legitimate security research purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations. The authors assume no liability for misuse of this software.

**Use this tool only on systems and processes you own or have explicit permission to test.**

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

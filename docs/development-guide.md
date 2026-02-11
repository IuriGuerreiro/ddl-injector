# Development Guide

This guide covers building, running, testing, and contributing to the DLL Injector project.

## Prerequisites

### Required Software
- **Rust** (1.75.0 or later)
  - Install: https://rustup.rs/
  - Verify: `rustc --version`
- **Windows 10/11** (x64)
  - Earlier versions may work but are untested
- **Visual Studio Build Tools** (for MSVC linker)
  - Install: https://visualstudio.microsoft.com/downloads/
  - Required components: "Desktop development with C++"

### Recommended Tools
- **VS Code** with rust-analyzer extension
- **RustRover** (JetBrains IDE for Rust)
- **Git** for version control
- **Windows Terminal** for better console experience

## Building the Project

### Clone Repository

```bash
git clone https://github.com/yourusername/dllInjector.git
cd dllInjector
```

### Build Debug Version

```bash
cargo build --workspace
```

This creates:
- `target/debug/injector.exe` - UI application
- `target/debug/injector_core.dll` - Core library

### Build Release Version

```bash
cargo build --workspace --release
```

This creates optimized binaries in `target/release/`:
- Smaller binary size (LTO enabled)
- Faster execution
- Stripped debug symbols

**Build time:**
- First build: ~5-10 minutes (downloads dependencies)
- Incremental builds: ~30 seconds

### Build Specific Crate

```bash
# Build only core library
cargo build -p injector-core

# Build only UI application
cargo build -p injector-ui --release
```

## Running the Application

### Run from Source

```bash
cargo run -p injector-ui
```

With logging:
```bash
RUST_LOG=debug cargo run -p injector-ui
```

### Run Built Binary

```bash
./target/release/injector.exe
```

## Testing

### Run All Tests

```bash
cargo test --workspace
```

### Run Tests for Specific Crate

```bash
cargo test -p injector-core
cargo test -p injector-ui
```

### Run Specific Test

```bash
cargo test test_enumerate_processes
```

### Run with Output

```bash
cargo test -- --nocapture
```

### Integration Tests

```bash
cargo test --test integration_tests
```

## Code Quality

### Run Clippy (Linter)

```bash
cargo clippy --workspace
```

Fix all warnings before committing.

### Format Code

```bash
cargo fmt --all
```

This project uses standard Rust formatting.

### Check Without Building

```bash
cargo check --workspace
```

Faster than full build, useful for quick validation.

## Project Structure

```
dllInjector/
├── Cargo.toml              # Workspace root
├── injector-core/          # Core library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # Public API
│       ├── process/        # Process management
│       ├── injection/      # Injection methods
│       ├── memory/         # Memory operations
│       ├── pe/             # PE parsing
│       └── privilege/      # Privilege elevation
├── injector-ui/            # GUI application
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # Entry point
│       ├── app.rs          # App state
│       ├── config.rs       # Configuration
│       └── ui/             # UI components
└── docs/                   # Documentation
    ├── phases/             # Implementation guides
    └── ...
```

## Dependencies

### Core Library
- `windows` - Windows API bindings
- `thiserror` - Error handling
- `log` - Logging facade

### UI Application
- `egui` - Immediate mode GUI
- `eframe` - egui framework
- `serde` - Serialization
- `rfd` - File dialogs
- `env_logger` - Logging implementation

### Updating Dependencies

```bash
cargo update
```

Check for outdated dependencies:
```bash
cargo outdated
```

## Debugging

### Debug Build

Debug builds include:
- Debug symbols
- Assertions enabled
- No optimizations (faster compile)

### Attach Debugger

**VS Code:**
1. Install "CodeLLDB" extension
2. Add breakpoint in code
3. Press F5 to start debugging

**RustRover:**
1. Add breakpoint
2. Click debug icon

### Logging

Use `log` macros throughout code:

```rust
log::trace!("Detailed debugging info");
log::debug!("Debug information");
log::info!("General information");
log::warn!("Warning messages");
log::error!("Error messages");
```

Set log level:
```bash
RUST_LOG=debug cargo run
```

## Performance Profiling

### Build with Profiling

```bash
cargo build --release --profile profiling
```

Add to `Cargo.toml`:
```toml
[profile.profiling]
inherits = "release"
debug = true
```

### Use Windows Performance Analyzer

1. Build release binary
2. Open Windows Performance Recorder
3. Start recording
4. Run application
5. Stop recording
6. Analyze in WPA

## Contributing

### Code Style

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Fix all `cargo clippy` warnings
- Add documentation comments to public items

### Commit Messages

Use conventional commits format:

```
<type>: <description>

[optional body]

[optional footer]
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Adding tests
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

**Example:**
```
feat: add QueueUserAPC injection method

- Implement thread enumeration
- Add APC queueing to all threads
- Include tests and documentation

Follows docs/phases/phase-07-advanced-methods.md
```

### Pull Request Process

1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes following code style
4. Add tests for new functionality
5. Ensure all tests pass: `cargo test --workspace`
6. Run clippy: `cargo clippy --workspace`
7. Format code: `cargo fmt --all`
8. Commit changes with good message
9. Push to your fork
10. Create pull request

### Testing Requirements

All PRs must:
- ✅ Pass all existing tests
- ✅ Include tests for new functionality
- ✅ Have no clippy warnings
- ✅ Be formatted with `cargo fmt`
- ✅ Include documentation for public APIs

## Troubleshooting

### Build Errors

**Error: linker not found**
```
Solution: Install Visual Studio Build Tools
```

**Error: windows-sys version mismatch**
```
Solution: cargo clean && cargo build
```

**Error: permission denied**
```
Solution: Close running instances of the application
```

### Runtime Errors

**Application won't start**
- Check graphics drivers are up to date
- Try running in compatibility mode
- Check Windows event viewer for crashes

**Injection fails with access denied**
- Run as administrator
- Check SeDebugPrivilege is enabled
- Target may be protected process

**DLL not found**
- Use absolute paths, not relative
- Verify DLL file exists
- Check file permissions

See [Troubleshooting Guide](troubleshooting.md) for more details.

## Release Process

### Version Bumping

Update version in `Cargo.toml` files:
```toml
[package]
version = "0.2.0"
```

### Create Release Build

```bash
cargo build --release
```

### Create Release Tag

```bash
git tag -a v0.2.0 -m "Release version 0.2.0"
git push origin v0.2.0
```

### Build Artifacts

Release includes:
- `injector.exe` - Standalone executable
- Documentation (PDF or HTML)
- LICENSE file
- README.md

## Environment Variables

### Logging
- `RUST_LOG=debug` - Debug level logging
- `RUST_LOG=trace` - Verbose logging
- `RUST_LOG=info` - Default logging

### Configuration
- `INJECTOR_CONFIG_DIR` - Custom config directory
- `INJECTOR_LOG_DIR` - Custom log directory

## Platform-Specific Notes

### Windows 10
- Fully supported
- Recommended platform

### Windows 11
- Fully supported
- May have additional security restrictions

### Wine/Linux
- Not supported
- Windows-specific APIs used throughout

## Getting Help

### Documentation
- [Architecture Overview](architecture.md)
- [Injection Methods](injection-methods.md)
- [Troubleshooting](troubleshooting.md)
- [Phase Guides](phases/)

### Community
- GitHub Issues: Report bugs
- GitHub Discussions: Ask questions
- Pull Requests: Contribute code

## License

This project is dual-licensed under MIT or Apache 2.0.

See LICENSE-MIT and LICENSE-APACHE files for details.

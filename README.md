# DLL Injector

> **A multi-method DLL injection framework for Windows, built in Rust with a modern GUI**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)

Educational DLL injection tool featuring four distinct injection methods, a modern GUI application, and a powerful library for integration into your own projects.

---

## ⚠️ Legal Notice

**This software is for educational, research, and authorized testing purposes ONLY.**

By using this software, you agree to:
- Only inject into processes you own or have explicit authorization to modify
- Never use for cheating in games or bypassing security systems
- Comply with all applicable laws and Terms of Service
- Accept full responsibility for your actions

**See [Legal Disclaimer](docs/legal-disclaimer.md) for complete details.**

Misuse can result in account bans, legal action, and criminal prosecution. **Use responsibly!**

---

## ✨ Features

### 🎯 Four Injection Methods

- **CreateRemoteThread** - Classic injection via remote thread creation (maximum compatibility)
- **QueueUserAPC** - Asynchronous procedure call injection (stealthy, requires alertable thread)
- **NtCreateThreadEx** - Native API injection (bypasses some user-mode hooks)
- **Manual Map** - Advanced memory mapping (stealth, bypasses module list)

### 🖥️ Modern User Interface

- **Intuitive GUI** built with [egui](https://github.com/emilk/egui)
- Real-time process enumeration with search filtering
- Live log viewer with persistent file logging
- Settings management with configuration persistence
- Recent DLLs list for quick access

### 🛡️ Safe & Reliable

- **Memory safety** - Built in Rust, eliminates entire classes of bugs
- **Comprehensive error handling** - Clear error messages and logging
- **Privilege management** - Automatic SeDebugPrivilege elevation
- **Architecture validation** - Prevents 32/64-bit mismatches

### 📚 Developer-Friendly

- **Library API** - Use `injector-core` in your own Rust projects
- **CLI tool** - `injector-cli` for automation and scripting
- **Code examples** - Working examples demonstrating all features
- **Complete documentation** - Architecture, API reference, user guide

---

## 📥 Installation

### Prerequisites

**Runtime:**
- Windows 10 or Windows 11 (64-bit recommended)
- Administrator privileges (required for injection)
- Microsoft Visual C++ Redistributable 2015-2022

**Build from source:**
- [Rust](https://rustup.rs/) 1.70 or later
- Visual Studio Build Tools 2019+

### Download Pre-built Binary

1. Download the latest release from [GitHub Releases](https://github.com/username/dllInjector/releases)
2. Extract to a folder (e.g., `C:\Tools\DLLInjector`)
3. Right-click `injector.exe` → "Run as administrator"

### Build from Source

```bash
# Clone the repository
git clone https://github.com/username/dllInjector.git
cd dllInjector

# Build release binaries
cargo build --workspace --release

# Output files in target/release/:
# - injector.exe        (GUI application)
# - injector-cli.exe    (command-line tool)
# - test_dll.dll        (test DLL for safe testing)
```

---

## 🚀 Quick Start

**Your first injection in 5 steps:**

```bash
# 1. Build the project (if not using pre-built binary)
cargo build --workspace --release

# 2. Start a test process (Notepad)
start notepad.exe

# 3. Run the GUI as administrator
# Right-click injector.exe → "Run as administrator"

# 4. In the GUI:
#    - Search for "notepad" in the process list
#    - Click Browse and select target/release/test_dll.dll
#    - Click "Inject DLL"

# 5. Success! A MessageBox should appear in Notepad
```

**Command-line quick start:**

```bash
# Using the CLI tool
injector-cli.exe notepad.exe C:\path\to\test_dll.dll

# Specify injection method
injector-cli.exe notepad.exe C:\path\to\test_dll.dll crt   # CreateRemoteThread
injector-cli.exe notepad.exe C:\path\to\test_dll.dll apc   # QueueUserAPC
injector-cli.exe notepad.exe C:\path\to\test_dll.dll nt    # NtCreateThreadEx
injector-cli.exe notepad.exe C:\path\to\test_dll.dll manual # Manual Map
```

**See the [User Guide](docs/user-guide.md) for comprehensive instructions.**

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [User Guide](docs/user-guide.md) | Complete guide for using the GUI application |
| [API Reference](docs/api-reference.md) | Library API documentation |
| [Architecture](docs/architecture.md) | Technical design and implementation details |
| [Testing Guide](docs/TESTING.md) | Test strategy and running tests |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |
| [Legal Disclaimer](docs/legal-disclaimer.md) | **Important legal information** |
| [Contributing](CONTRIBUTING.md) | How to contribute to the project |
| [Code Examples](injector-core/examples/README.md) | Working code examples |

---

## 📁 Project Structure

```
dllInjector/
├── injector-core/              # Core injection library (Rust crate)
│   ├── src/
│   │   ├── lib.rs              # Public API exports
│   │   ├── error.rs            # Error types and handling
│   │   ├── process/            # Process enumeration and handles
│   │   │   ├── enumerator.rs   # Process discovery
│   │   │   ├── handle.rs       # RAII process handles
│   │   │   └── thread.rs       # Thread enumeration
│   │   ├── injection/          # Injection method implementations
│   │   │   ├── create_remote_thread.rs
│   │   │   ├── queue_user_apc.rs
│   │   │   ├── nt_create_thread.rs
│   │   │   ├── manual_map.rs
│   │   │   └── traits.rs       # Common injection interface
│   │   ├── memory/             # Memory management
│   │   │   ├── allocation.rs   # Memory allocation/freeing
│   │   │   └── operations.rs   # Read/write operations
│   │   ├── pe/                 # PE file parsing
│   │   │   ├── parser.rs       # PE header parsing
│   │   │   ├── imports.rs      # Import resolution
│   │   │   └── relocations.rs  # Relocation processing
│   │   └── privilege/          # Privilege management
│   │       └── manager.rs      # SeDebugPrivilege handling
│   ├── examples/               # Usage examples
│   │   ├── basic_injection.rs  # Simple CreateRemoteThread example
│   │   ├── custom_injector.rs  # All methods with runtime selection
│   │   └── README.md           # Example documentation
│   └── Cargo.toml
│
├── injector-ui/                # GUI application (egui)
│   ├── src/
│   │   ├── main.rs             # Application entry point
│   │   ├── app.rs              # Main application state and logic
│   │   ├── config.rs           # Configuration management
│   │   ├── logging.rs          # Dual logger (file + UI)
│   │   └── ui/                 # UI components
│   │       ├── process_list.rs # Process list panel
│   │       ├── injection_panel.rs # Injection controls
│   │       ├── log_viewer.rs   # Log viewer panel
│   │       └── settings.rs     # Settings dialog
│   └── Cargo.toml
│
├── injector-cli/               # Command-line tool
│   ├── src/
│   │   └── main.rs             # CLI argument parsing and injection
│   └── Cargo.toml
│
├── test-dll/                   # Test DLL for safe testing
│   ├── src/
│   │   └── lib.rs              # MessageBox on injection
│   └── Cargo.toml
│
├── docs/                       # Documentation
│   ├── README.md               # Documentation index
│   ├── architecture.md         # Technical architecture
│   ├── api-reference.md        # API documentation
│   ├── user-guide.md           # User guide
│   ├── TESTING.md              # Testing guide
│   ├── troubleshooting.md      # Common issues
│   ├── legal-disclaimer.md     # Legal information
│   └── phases/                 # Phase-by-phase dev logs
│
├── LICENSE-MIT                 # MIT License
├── LICENSE-APACHE              # Apache 2.0 License
├── CONTRIBUTING.md             # Contributing guidelines
├── Cargo.toml                  # Workspace configuration
└── README.md                   # This file
```

---

## 🧪 Testing

```bash
# Run all tests
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_name

# Run integration tests
cargo test --test '*'

# Check code quality
cargo clippy --workspace -- -D warnings
cargo fmt --all --check
```

**Safe test targets:**
- `notepad.exe` - Simple, lightweight
- `calc.exe` - Calculator app
- `mspaint.exe` - Paint app

**See [TESTING.md](docs/TESTING.md) for complete testing documentation.**

---

## 🔧 Usage Examples

### GUI Application

```bash
# Run with cargo
cargo run --release -p injector-ui

# Or run the binary (as administrator!)
.\target\release\injector.exe
```

### Command-Line Interface

```bash
# Basic usage
injector-cli.exe <process_name_or_pid> <dll_path> [method]

# Examples
injector-cli.exe notepad.exe C:\test_dll.dll
injector-cli.exe 1234 C:\test_dll.dll crt
injector-cli.exe calc.exe C:\my.dll manual
```

### Library (Rust)

```rust
use injector_core::*;
use std::path::Path;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable debug privilege
    PrivilegeManager::enable_debug_privilege()?;

    // Find target process
    let processes = ProcessEnumerator::find_by_name("notepad")?;
    let target = processes.first().ok_or("Process not found")?;

    // Open process handle
    let handle = ProcessHandle::open(target.pid, PROCESS_ALL_ACCESS)?;

    // Inject DLL
    let injector = CreateRemoteThreadInjector;
    injector.inject(&handle, Path::new(r"C:\test.dll"))?;

    println!("Injection successful!");
    Ok(())
}
```

**See [examples/](injector-core/examples/) for more detailed examples.**

---

## 🎯 Injection Method Comparison

| Method | Compatibility | Stealth | Complexity | Best For |
|--------|---------------|---------|------------|----------|
| **CreateRemoteThread** | ✅ Excellent | ⚠️ Low | Simple | Maximum compatibility, testing |
| **QueueUserAPC** | ⚠️ Moderate | ✅ Good | Moderate | GUI apps, stealth |
| **NtCreateThreadEx** | ✅ Good | ✅ Good | Moderate | Bypassing hooks |
| **Manual Map** | ⚠️ Limited | ✅✅ Excellent | Complex | Maximum stealth, simple DLLs |

**See [User Guide](docs/user-guide.md#injection-methods) for detailed comparison.**

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting PRs.

**By contributing, you certify that:**
- Your contribution is your original work or you have rights to contribute it
- You agree to license it under MIT OR Apache-2.0
- You understand and agree to the [legal disclaimer](docs/legal-disclaimer.md)
- Your contribution is for educational/authorized purposes only

**Areas we welcome contributions:**
- Bug fixes and stability improvements
- Performance optimizations
- Documentation improvements
- Additional injection methods (educational value)
- Better error messages and diagnostics
- UI/UX enhancements
- Test coverage improvements

---

## 📜 License

Licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- **MIT license** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

## 🙏 Acknowledgments

- **[egui](https://github.com/emilk/egui)** - Immediate mode GUI framework
- **[windows-rs](https://github.com/microsoft/windows-rs)** - Rust bindings for Windows API
- **[thiserror](https://github.com/dtolnay/thiserror)** - Error handling macros
- **Rust Community** - For excellent tooling and support

---

## ⚡ Disclaimer

```
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

**Translation:** The authors are not responsible for how you use this software. You use it at your own risk.

This tool was created for educational purposes to demonstrate:
- Windows internals and process management
- PE file format and memory layout
- Systems programming in Rust
- Security concepts and techniques

**It is a learning tool, not a cheating tool.**

---

## 📞 Contact & Support

- **Issues:** [GitHub Issues](https://github.com/username/dllInjector/issues)
- **Discussions:** [GitHub Discussions](https://github.com/username/dllInjector/discussions)
- **Security:** Report vulnerabilities privately (see CONTRIBUTING.md)

**For legal questions, consult an attorney. The authors cannot provide legal advice.**

---

**Made with ❤️ and Rust** | **Use responsibly** | **Learn ethically**

---

**Last Updated:** 2026-02-12
**Version:** 0.1.0
**Minimum Rust Version:** 1.70+

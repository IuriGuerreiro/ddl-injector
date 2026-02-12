# DLL Injector Documentation

Welcome to the DLL Injector documentation. This directory contains comprehensive guides for understanding, building, and extending the DLL injector tool.

## Documentation Index

### Getting Started
- **[Quick Start](../README.md)** - Main project README with quick start guide
- **[User Guide](user-guide.md)** - Complete guide for using the GUI application
- **[Architecture Overview](architecture.md)** - High-level system design and component interaction
- **[Development Guide](development-guide.md)** - How to build, run, and contribute

### Technical Deep Dives
- **[Injection Methods](injection-methods.md)** - Detailed explanation of each injection technique
- **[API Reference](api-reference.md)** - Complete public API documentation for `injector-core` library
- **[Testing Guide](TESTING.md)** - Comprehensive test strategy and running tests
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

### Implementation Phases

The project is built in 11 phases, each with detailed implementation documentation:

| Phase | Name | Description | Status |
|-------|------|-------------|--------|
| 0 | [Documentation Foundation](phases/phase-00-documentation.md) | Create all phase subplans | ✅ Complete |
| 1 | [Project Foundation](phases/phase-01-foundation.md) | Cargo workspace setup | ✅ Complete |
| 2 | [Process Enumeration](phases/phase-02-process-enum.md) | Process discovery and handles | ✅ Complete |
| 3 | [Basic Injection](phases/phase-03-basic-injection.md) | CreateRemoteThread method | ✅ Complete |
| 4 | [UI Foundation](phases/phase-04-ui-foundation.md) | egui interface setup | ✅ Complete |
| 5 | [Privilege Elevation](phases/phase-05-privileges.md) | SeDebugPrivilege handling | ✅ Complete |
| 6 | [Manual Mapping](phases/phase-06-manual-mapping.md) | PE parsing and manual map | ✅ Complete |
| 7 | [Advanced Methods](phases/phase-07-advanced-methods.md) | APC and NtCreateThreadEx | ✅ Complete |
| 8 | [Configuration](phases/phase-08-config.md) | Settings persistence | ✅ Complete |
| 9 | [Logging](phases/phase-09-logging.md) | Enhanced logging system | ✅ Complete |
| 10 | [Testing](phases/phase-10-testing.md) | Comprehensive test suite | ✅ Complete |
| 11 | [Polish](phases/phase-11-polish.md) | Documentation and examples | ✅ Complete |

### Legal
- **[Legal Disclaimer](legal-disclaimer.md)** - Important information about responsible use

## Documentation Philosophy

This project follows a **documentation-first** approach:

1. **Phase 0** creates detailed subplans for all implementation phases
2. Each phase has a comprehensive guide with:
   - Step-by-step implementation instructions
   - Code templates and examples
   - Windows API usage details
   - Error handling strategies
   - Testing checklists
   - Common pitfalls to avoid
3. Implementation follows the documented plan, not the other way around

This ensures clarity, prevents rework, and provides a learning resource for developers.

## Contributing

Contributions are welcome! See:
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contributing guidelines and code of conduct
- **[Development Guide](development-guide.md)** - Setting up development environment
- **[Testing Guide](TESTING.md)** - Running and writing tests
- **[Code Examples](../injector-core/examples/README.md)** - Example usage patterns

## Support

For issues, questions, or contributions:
- Check [Troubleshooting](troubleshooting.md) for common problems
- Review the relevant phase documentation
- Check existing issues and pull requests

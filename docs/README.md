# DLL Injector Documentation

Welcome to the DLL Injector documentation. This directory contains comprehensive guides for understanding, building, and extending the DLL injector tool.

## Documentation Index

### Getting Started
- **[Architecture Overview](architecture.md)** - High-level system design and component interaction
- **[Development Guide](development-guide.md)** - How to build, run, and contribute
- **[Quick Start](../README.md)** - Main project README with quick start guide

### Technical Deep Dives
- **[Injection Methods](injection-methods.md)** - Detailed explanation of each injection technique
- **[API Reference](api-reference.md)** - Public API documentation for `injector-core`
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

### Implementation Phases

The project is built in 11 phases, each with detailed implementation documentation:

| Phase | Name | Description | Status |
|-------|------|-------------|--------|
| 0 | [Documentation Foundation](phases/phase-00-documentation.md) | Create all phase subplans | ✅ Current |
| 1 | [Project Foundation](phases/phase-01-foundation.md) | Cargo workspace setup | ⏳ Pending |
| 2 | [Process Enumeration](phases/phase-02-process-enum.md) | Process discovery and handles | ⏳ Pending |
| 3 | [Basic Injection](phases/phase-03-basic-injection.md) | CreateRemoteThread method | ⏳ Pending |
| 4 | [UI Foundation](phases/phase-04-ui-foundation.md) | egui interface setup | ⏳ Pending |
| 5 | [Privilege Elevation](phases/phase-05-privileges.md) | SeDebugPrivilege handling | ⏳ Pending |
| 6 | [Manual Mapping](phases/phase-06-manual-mapping.md) | PE parsing and manual map | ⏳ Pending |
| 7 | [Advanced Methods](phases/phase-07-advanced-methods.md) | APC and NtCreateThreadEx | ⏳ Pending |
| 8 | [Configuration](phases/phase-08-config.md) | Settings persistence | ⏳ Pending |
| 9 | [Logging](phases/phase-09-logging.md) | Enhanced logging system | ⏳ Pending |
| 10 | [Testing](phases/phase-10-testing.md) | Comprehensive test suite | ⏳ Pending |
| 11 | [Polish](phases/phase-11-polish.md) | Documentation and examples | ⏳ Pending |

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

See the [Development Guide](development-guide.md) for information on:
- Setting up your development environment
- Building the project
- Running tests
- Submitting changes

## Support

For issues, questions, or contributions:
- Check [Troubleshooting](troubleshooting.md) for common problems
- Review the relevant phase documentation
- Check existing issues and pull requests

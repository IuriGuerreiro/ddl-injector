# Contributing to DLL Injector

Thank you for your interest in contributing to this project! We welcome contributions that improve the educational value, code quality, and functionality of this tool.

## ⚠️ Code of Conduct: Responsible Use Only

**Before contributing, you must understand and agree to the following:**

This project is for **educational, research, and authorized testing purposes only**. All contributions must align with this principle. We do **NOT** accept contributions that:

- Facilitate cheating in online games
- Bypass anti-cheat or security systems for malicious purposes
- Enable unauthorized access to systems
- Promote or enable illegal activities

**Please read our [Legal Disclaimer](docs/legal-disclaimer.md) thoroughly before contributing.**

## How to Contribute

### Reporting Issues

**Security Vulnerabilities:**
- Do NOT open public issues for security vulnerabilities
- Email security concerns privately (see README for contact)
- We will coordinate responsible disclosure

**Bug Reports:**
- Search existing issues first to avoid duplicates
- Use a clear, descriptive title
- Include:
  - Steps to reproduce
  - Expected behavior
  - Actual behavior
  - Windows version
  - Rust version (`rustc --version`)
  - Error messages or logs

**Feature Requests:**
- Explain the use case (must be educational/authorized)
- Describe the proposed solution
- Consider if it aligns with project goals
- Tag with `enhancement`

### Development Setup

**Prerequisites:**
- Windows 10/11 (64-bit recommended)
- Rust 1.70 or later (install via [rustup](https://rustup.rs/))
- Visual Studio Build Tools 2019+ (for MSVC linker)
- Git

**Clone and Build:**
```bash
# Clone the repository
git clone https://github.com/username/dllInjector.git
cd dllInjector

# Build all workspace members
cargo build --workspace

# Run tests
cargo test --workspace

# Build release version
cargo build --workspace --release
```

**Development Tools:**
```bash
# Install formatting and linting tools
rustup component add rustfmt clippy

# Check formatting
cargo fmt --all --check

# Run linter
cargo clippy --workspace -- -D warnings
```

### Code Style and Standards

**Formatting:**
- Use `cargo fmt` to format all code before committing
- 4-space indentation (enforced by rustfmt)
- 100-character line limit where practical

**Linting:**
- All code must pass `cargo clippy --workspace -- -D warnings`
- Fix clippy warnings; don't suppress unless absolutely necessary
- Document why if you must use `#[allow(...)]`

**Naming Conventions:**
- Types: `PascalCase` (e.g., `ProcessHandle`, `InjectionMethod`)
- Functions/methods: `snake_case` (e.g., `inject_dll`, `get_process_id`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `MAX_PATH`, `DEFAULT_TIMEOUT`)
- Follow Rust API Guidelines: https://rust-lang.github.io/api-guidelines/

**Documentation:**
- Public APIs must have doc comments (`///`)
- Include examples for complex functions
- Document safety requirements for `unsafe` code
- Explain error conditions

**Error Handling:**
- Use `Result<T, InjectionError>` for fallible operations
- Provide helpful error messages
- Chain errors with context using `map_err`
- Never unwrap/expect in library code (tests are ok)

### Testing Requirements

**All contributions must include tests.**

**Unit Tests:**
- Test individual functions/methods
- Mock external dependencies where possible
- Place in module with `#[cfg(test)]`

**Integration Tests:**
- Test complete workflows
- Use `test_dll.dll` from `test-dll/` for safe testing
- Place in `tests/` directory

**Running Tests:**
```bash
# Run all tests
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_name

# Run integration tests only
cargo test --test '*'
```

**Test Coverage:**
- Aim for >80% code coverage for new features
- Test error paths, not just happy paths
- Include edge cases (null pointers, invalid handles, etc.)

### Commit Conventions

We use conventional commits for clear history and changelog generation.

**Format:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting changes (no code logic change)
- `refactor`: Code restructuring (no behavior change)
- `test`: Adding or updating tests
- `chore`: Maintenance tasks (dependencies, build scripts)
- `perf`: Performance improvements

**Scope (optional):**
- `core`: injector-core library
- `ui`: injector-ui application
- `cli`: injector-cli application
- `examples`: Example code
- `tests`: Test infrastructure

**Examples:**
```
feat(core): add QueueUserAPC injection method

Implements user-mode APC injection as an alternative to
CreateRemoteThread. Includes comprehensive error handling
and tests.

Closes #42

---

fix(ui): prevent crash when process list is empty

Added null check before accessing first element of process list.

---

docs: add troubleshooting guide for common errors

---

test(core): add integration tests for all injection methods
```

### Pull Request Process

**Before Submitting:**
1. Ensure all tests pass: `cargo test --workspace`
2. Run formatter: `cargo fmt --all`
3. Run clippy: `cargo clippy --workspace -- -D warnings`
4. Update documentation if you changed APIs
5. Add tests for new functionality
6. Update CHANGELOG.md if applicable

**PR Guidelines:**
- Use a clear, descriptive title
- Reference related issues (e.g., "Fixes #123")
- Describe what changes were made and why
- Include screenshots for UI changes
- Keep PRs focused (one feature/fix per PR)
- Be responsive to review feedback

**PR Template:**
```markdown
## Description
Brief description of changes

## Related Issues
Fixes #123

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] Documentation updated
- [ ] No new warnings from clippy
- [ ] Formatted with cargo fmt
```

**Review Process:**
1. Automated checks run (CI/CD if configured)
2. Maintainer reviews code
3. Address feedback
4. Approval and merge

### Security and Legal Compliance

**Security Best Practices:**
- Never commit sensitive data (tokens, passwords, etc.)
- Validate all user input
- Use safe Rust where possible; minimize `unsafe`
- Document all safety invariants for `unsafe` code
- Check for vulnerabilities: `cargo audit`

**Legal Compliance:**
- Contributions must not violate CFAA, DMCA, or similar laws
- Do not include code that bypasses security for malicious purposes
- Respect intellectual property rights
- Ensure you have rights to contribute code

**By Contributing:**
You certify that:
1. Your contribution is your original work or you have rights to contribute it
2. You agree to license it under MIT OR Apache-2.0
3. You understand and agree to the legal disclaimer
4. Your contribution is for educational/authorized purposes only

### Areas We Welcome Contributions

**Encouraged:**
- Bug fixes and stability improvements
- Performance optimizations
- Documentation improvements
- Additional injection methods (educational value)
- Better error messages and diagnostics
- Cross-platform compatibility (if applicable)
- Test coverage improvements
- UI/UX enhancements
- Example code and tutorials

**Discouraged:**
- Features that primarily enable game cheating
- Anti-detection techniques
- Bypassing security measures
- Obfuscation or evasion techniques
- Anything violating the legal disclaimer

### Getting Help

**Questions:**
- Open a GitHub Discussion for general questions
- Use Issues for specific bugs/features
- Check existing documentation first

**Resources:**
- [README.md](README.md) - Project overview
- [docs/architecture.md](docs/architecture.md) - Technical design
- [docs/api-reference.md](docs/api-reference.md) - API documentation
- [docs/TESTING.md](docs/TESTING.md) - Testing guide
- [docs/legal-disclaimer.md](docs/legal-disclaimer.md) - Legal information

## Development Workflow

**Typical workflow for a contribution:**

1. **Fork and clone:**
   ```bash
   git clone https://github.com/yourusername/dllInjector.git
   cd dllInjector
   ```

2. **Create a branch:**
   ```bash
   git checkout -b feat/your-feature-name
   ```

3. **Make changes:**
   - Write code
   - Add tests
   - Update documentation

4. **Verify quality:**
   ```bash
   cargo test --workspace
   cargo clippy --workspace -- -D warnings
   cargo fmt --all --check
   ```

5. **Commit changes:**
   ```bash
   git add .
   git commit -m "feat: add your feature"
   ```

6. **Push and create PR:**
   ```bash
   git push origin feat/your-feature-name
   ```
   Then open a pull request on GitHub.

7. **Address review feedback:**
   - Make requested changes
   - Push additional commits
   - Respond to comments

## Release Process

**For Maintainers:**

Releases follow semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking API changes
- MINOR: New features (backwards compatible)
- PATCH: Bug fixes

**Release steps:**
1. Update version in all `Cargo.toml` files
2. Update CHANGELOG.md
3. Create git tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
4. Push tag: `git push origin v1.0.0`
5. Build release binaries
6. Create GitHub release with binaries and changelog

## Recognition

Contributors will be acknowledged in:
- README.md acknowledgments section
- Git commit history
- Release notes

Thank you for helping make this project better while keeping it responsible and educational!

## Questions?

If you have questions about contributing:
- Check existing documentation
- Search closed issues
- Open a discussion on GitHub
- Be patient and respectful

We appreciate your interest in contributing responsibly!

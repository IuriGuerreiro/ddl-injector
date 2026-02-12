# Project Review and Injection Method Expansion Report

This report reviews the current project implementation and recommends what should change next, with a specific focus on expanding supported injection techniques safely and realistically.

## Executive Summary

The project is in a strong starting position:
- Clear workspace split (`injector-core`, `injector-cli`, `injector-ui`)
- Four implemented methods (CreateRemoteThread, QueueUserAPC, NtCreateThreadEx, Manual Map)
- Good supporting modules for process/thread inspection, PE parsing, and privilege management

The biggest opportunity now is to move from "multiple methods" to a **capability-driven injector platform**: add new methods based on operational value, document method constraints, and standardize fallback behavior when one method fails.

---

## Current Gaps to Address

## 1) Method Selection Is Not Yet Strategy-Driven

The project supports multiple techniques, but users still need clearer guidance on when each method should be used.

### Recommended change
- Add a **method planner** layer in `injector-core` that selects methods based on:
  - target architecture
  - privilege level
  - process mitigation policies
  - desired trade-off (`reliability`, `stealth`, `speed`)

## 2) Method Capability Documentation Needs a Single Matrix

Current docs explain methods individually, but users need one place showing hard limits and expected behavior.

### Recommended change
- Add a compact matrix in `docs/injection-methods.md` covering:
  - required rights
  - new thread required?
  - loader artifacts left behind
  - common fail reasons
  - support level (`stable`, `experimental`, `research`)

## 3) Manual Map Needs Explicit Scope Boundary

Manual mapping is complex and should have explicit guarantees (what is supported) and explicit non-goals.

### Recommended change
- Define supported PE features in docs and code-level validation errors (TLS callbacks, SEH/runtime, delay imports, CLR, etc.).
- Add negative tests for unsupported edge cases to fail early and clearly.

---

## New Injection Methods to Add (Prioritized)

These are suggested in order of practical value and implementation risk.

## Priority 1 (High value, moderate complexity)

### A) Thread Hijacking Injection

**Why add it:**
- Avoids creating a brand-new remote thread.
- Useful fallback where direct remote thread creation is heavily monitored.

**Implementation outline:**
1. Suspend a target thread.
2. Save thread context.
3. Write a small stub + DLL path (or shellcode loader) into remote memory.
4. Set instruction pointer to the stub.
5. Resume thread; later restore original context.

**Notes:**
- Must be architecture-specific (x64 context handling).
- Requires careful crash-safe restoration logic.

### B) Section Mapping / Shared Section Injection

**Why add it:**
- Can reduce obvious `WriteProcessMemory` usage by mapping a section into both processes.
- Good intermediate step between classic injection and advanced stealth paths.

**Implementation outline:**
- Use native section APIs (`NtCreateSection`, `NtMapViewOfSection`) to stage payload.
- Trigger execution via existing launch primitive (e.g., NtCreateThreadEx/hijack).

**Notes:**
- Keep this as `experimental` first; provide strong telemetry when it fails.

## Priority 2 (Good coverage expansion)

### C) Early Bird APC Injection

**Why add it:**
- Better APC reliability pattern by queueing before normal user code execution.
- Complements existing QueueUserAPC support.

**Implementation outline:**
- Create target process suspended.
- Queue APC to primary thread.
- Resume thread to execute APC early in lifecycle.

**Notes:**
- Requires process creation flow (not just attach-to-existing PID).

### D) Reflective Loader Mode (for compatible payloads)

**Why add it:**
- Useful for payloads that include a reflective loader entrypoint.
- Gives more flexibility than plain LoadLibrary-based techniques.

**Implementation outline:**
- Inject reflective loader blob + parameters.
- Execute exported reflective entrypoint.

**Notes:**
- Should be opt-in and clearly labeled due to payload compatibility requirements.

## Priority 3 (Research-oriented / optional)

### E) Process Hollowing (new process replacement)

**Why add it:**
- Valuable for research and understanding process creation internals.

**Notes:**
- Not a direct DLL injection into a live process; should be in a separate "process replacement" category.
- High complexity and security sensitivity; keep out of default UI path initially.

### F) Module Stomping / AddressOfEntryPoint Stomping

**Why add it:**
- Research technique for studying detection and forensic traces.

**Notes:**
- Higher risk of instability and easy misuse.
- Recommend `research` label with explicit warnings.

---

## Methods to Avoid (or Defer)

- Kernel-mode techniques (driver-based): out of scope for this user-mode Rust project.
- "Undetectable" claims: should never be presented in docs or UI.
- Highly exploit-dependent methods (e.g., atom bombing variants) unless there is a clear educational scope and test plan.

---

## Architectural Changes Needed to Support More Methods

1. **Standardized method contract**
   - Extend trait metadata to report capabilities, prerequisites, and failure categories.
2. **Preflight analyzer**
   - Add a reusable preflight phase (rights, architecture, target state, mitigation policies).
3. **Fallback chain execution**
   - Let users choose "auto mode" with deterministic fallback order and full logging.
4. **Unified telemetry schema**
   - Every method should emit comparable events (allocation, write, execution trigger, cleanup).
5. **Risk labels in UI/CLI**
   - Display method maturity and expected side effects directly where the method is selected.

---

## Testing and Release Recommendations for Method Expansion

- Add per-method smoke tests (where feasible) plus documented manual validation scripts.
- Introduce method-specific fixture DLLs:
  - simple DLL (baseline)
  - TLS-heavy DLL
  - exception-heavy DLL
  - import-heavy DLL
- Add a Windows CI lane that at least builds all methods and runs non-privileged validations.
- Add release checklist items requiring:
  - docs matrix update
  - failure-mode update in troubleshooting
  - method maturity label review

---

## Suggested 90-Day Roadmap

### Phase 1 (Weeks 1-3)
- Implement capability matrix + method metadata
- Add preflight analyzer and fallback chain
- Improve docs to show method support levels

### Phase 2 (Weeks 4-7)
- Implement Thread Hijacking (experimental)
- Implement Early Bird APC (experimental)
- Add targeted tests + troubleshooting playbooks

### Phase 3 (Weeks 8-12)
- Implement Section Mapping injection (experimental)
- Stabilize two methods to `stable` based on test outcomes
- Evaluate whether reflective mode belongs in mainline or separate feature flag

---

## Final Recommendation

The project should prioritize becoming **predictable and transparent** before chasing every exotic technique. The best next step is to add **Thread Hijacking**, **Early Bird APC**, and **Section Mapping** with strong preflight checks, fallback logic, and honest support labels. That combination expands real capability while preserving maintainability and user trust.

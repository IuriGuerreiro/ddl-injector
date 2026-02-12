# Legacy Project Review (Non-UI)

This document reviews the current state of the project from a maintainability, reliability, and delivery perspective, focusing on backend/core, CLI, docs, and engineering workflow.

## Executive Summary

The project has a solid high-level architecture (workspace split into `injector-core`, `injector-cli`, and `injector-ui`) and good intent around safety and modularity. However, it is currently held back by **documentation drift**, **test strategy gaps**, and **platform-coupled assumptions** that reduce confidence for contributors and users.

## What Could Be Improved

## 1) Documentation Accuracy and Single Source of Truth

**Observed issue:**
- Root docs show many phases as "planned" even though substantial code is already present.
- Testing docs and examples include machine-specific absolute paths.
- Some architectural descriptions no longer match current trait signatures and implementation details.

**Why this matters:**
- New contributors cannot trust docs to reflect implementation.
- Onboarding and troubleshooting become slower and error-prone.

**Recommended improvements:**
- Replace phase/status tables with a concise "implemented / partial / planned" matrix generated from real crate capabilities.
- Remove hard-coded local paths from examples and use workspace-relative examples.
- Add a "docs verification" checklist to PRs (API signatures, method names, and flow descriptions checked against code).

## 2) Testing Strategy and CI Realism

**Observed issue:**
- Several tests are Windows-only by nature, and one integration test is ignored and relies on a local drive path.
- There is no clear split between fast deterministic tests and privileged/manual validation.

**Why this matters:**
- Test results are hard to trust and difficult to run consistently in automation.

**Recommended improvements:**
- Introduce test tiers:
  - **Tier A:** platform-agnostic/unit tests (always run in CI).
  - **Tier B:** Windows-only tests gated with target cfg and deterministic fixtures.
  - **Tier C:** privileged/manual tests (documented and opt-in).
- Replace environment-specific fixture paths with generated or repository-scoped fixtures.
- Add at least one CI lane for `x86_64-pc-windows-msvc` with feature-limited checks where full integration cannot run.

## 3) Safety Boundaries Around `unsafe` and FFI Calls

**Observed issue:**
- Core injection paths use many FFI operations and pointer transmutations.
- Safety assumptions are mostly implicit and spread across files.

**Why this matters:**
- Auditing and long-term maintenance are harder when invariants are not explicit.

**Recommended improvements:**
- Add a safety-comment standard for every `unsafe` block (preconditions + postconditions).
- Isolate high-risk FFI operations in narrow wrappers with typed inputs/outputs.
- Add negative tests around validation logic (path checks, architecture mismatch, PE parsing failures).

## 4) Error Taxonomy and Operator Guidance

**Observed issue:**
- Error enums are fairly comprehensive, but recovery guidance is inconsistent between CLI/log output and docs.

**Why this matters:**
- Users may receive an error without clear remediation steps.

**Recommended improvements:**
- Map each major error variant to "likely cause" + "next action" in troubleshooting docs.
- Standardize error presentation in CLI/core so messages contain actionable hints.
- Consider error codes/categories for easier automation and telemetry.

## 5) Feature Completeness and Capability Signaling

**Observed issue:**
- Method list is broad, but practical capability boundaries are not always communicated in one place.

**Why this matters:**
- Users may expect parity across methods where edge cases differ.

**Recommended improvements:**
- Add a capability matrix per injection method (requirements, stealth characteristics, expected failure modes, architecture limits).
- Document support level labels (`experimental`, `stable`, `manual-test-only`) per method.

## 6) Operational Hardening

**Observed issue:**
- The project does not yet present an explicit hardening checklist for releases.

**Why this matters:**
- Security-sensitive tooling needs repeatable release hygiene.

**Recommended improvements:**
- Add a release checklist covering dependency audit, symbol stripping policy, logging defaults, and legal/research-use reminders.
- Pin and review dependencies on a cadence.

---

## What Likely Cannot Be Improved (or Only Limited Improvement Is Possible)

These are mostly constraints of the domain and platform, not project quality issues:

1. **Privilege requirements are fundamental**  
   Injecting into protected or higher-integrity processes often requires elevated rights. Tooling can improve messaging, but cannot remove OS privilege boundaries.

2. **Cross-architecture constraints are inherent**  
   32-bit ↔ 64-bit mismatch limitations are rooted in process architecture and Windows loader/runtime behavior. Validation can be improved, but the limitation remains.

3. **Detection surface cannot be eliminated**  
   Different methods reduce or shift detection vectors, but no injection approach is universally undetectable against modern anti-cheat/EDR defenses.

4. **Manual mapping complexity has unavoidable edge cases**  
   TLS callbacks, exception registration, relocations, imports, and loader-like behavior create unavoidable complexity and compatibility edge cases.

5. **Windows-specific nature of core functionality**  
   The core problem space is tightly coupled to Windows APIs. Portability to non-Windows can improve tooling around it, but not the underlying injection mechanics.

---

## Practical Next Steps (Priority Order)

1. **Fix documentation drift first** (highest leverage for all contributors).
2. **Implement the 3-tier testing model with CI gates**.
3. **Harden unsafe/FFI boundaries with explicit safety contracts**.
4. **Publish capability and support-level matrices per injection method**.
5. **Add release hardening checklist and dependency review cadence**.

If these five are executed, the project becomes significantly easier to maintain, safer to evolve, and clearer for external reviewers.

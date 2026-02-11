# DLL Injection Methods

This document explains the theory and implementation details of each DLL injection technique supported by this project.

## Overview

DLL injection is the process of forcing a target process to load and execute code from a Dynamic Link Library (DLL). This is useful for:
- **Game modding** - Extending game functionality
- **Debugging** - Instrumenting applications
- **Testing** - Hooking APIs for testing
- **Security research** - Analyzing application behavior

## Table of Contents

1. [CreateRemoteThread Injection](#1-createremotethread-injection)
2. [Manual Mapping](#2-manual-mapping)
3. [QueueUserAPC Injection](#3-queueuserapc-injection)
4. [NtCreateThreadEx Injection](#4-ntcreatethreadex-injection)
5. [Comparison Matrix](#comparison-matrix)

---

## 1. CreateRemoteThread Injection

### Overview
The classic and most widely-known DLL injection technique. Uses Windows API functions to create a thread in the target process that calls `LoadLibraryA` with the DLL path.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Injector Process                                       │
├─────────────────────────────────────────────────────────┤
│  1. OpenProcess(target_pid)                             │
│     └─> Get HANDLE to target process                    │
│                                                          │
│  2. VirtualAllocEx(target_handle, dll_path_size)        │
│     └─> Allocate memory in target's address space       │
│                                                          │
│  3. WriteProcessMemory(target, dll_path)                │
│     └─> Write DLL path string to allocated memory       │
│                                                          │
│  4. GetProcAddress(kernel32, "LoadLibraryA")            │
│     └─> Get address of LoadLibraryA (same in all procs) │
│                                                          │
│  5. CreateRemoteThread(target, LoadLibraryA, dll_path)  │
│     └─> Start thread in target that calls LoadLibraryA  │
└─────────────────────────────────────────────────────────┘
                          │
                          ↓
┌─────────────────────────────────────────────────────────┐
│  Target Process                                         │
├─────────────────────────────────────────────────────────┤
│  New Thread Created:                                    │
│  └─> Executes: LoadLibraryA("C:\\path\\to\\dll.dll")   │
│       └─> Loads DLL into process                        │
│            └─> Calls DllMain(DLL_PROCESS_ATTACH)        │
│                └─> Your code executes!                  │
└─────────────────────────────────────────────────────────┘
```

### Advantages
✅ Simple to understand and implement
✅ High reliability (well-tested Windows API)
✅ Works on all Windows versions
✅ Proper DLL initialization (DllMain called)

### Disadvantages
❌ Easy to detect (CreateRemoteThread is commonly hooked)
❌ DLL appears in loaded modules list
❌ Obvious in process memory
❌ Requires write permission to target process

### Detection Vectors
- Anti-cheat can hook `CreateRemoteThread` in kernel
- Monitoring tools can detect remote thread creation
- DLL shows in `EnumProcessModules` / Task Manager
- Security software alerts on suspicious thread creation

### Implementation Notes

**Required Privileges:**
- `PROCESS_CREATE_THREAD`
- `PROCESS_VM_OPERATION`
- `PROCESS_VM_WRITE`
- Often requires `SeDebugPrivilege` for protected processes

**Common Pitfalls:**
1. **Relative paths don't work** - Must use absolute path to DLL
2. **Architecture mismatch** - Can't inject 32-bit DLL into 64-bit process
3. **Kernel32.dll address** - LoadLibraryA address must be obtained correctly
4. **Memory leaks** - Must free allocated memory even on error

**Rust Implementation Sketch:**
```rust
pub struct CreateRemoteThreadInjector;

impl InjectionMethod for CreateRemoteThreadInjector {
    fn inject(&self, target_pid: u32, dll_path: &Path) -> Result<(), InjectionError> {
        // 1. Validate DLL path is absolute
        let dll_path_abs = dll_path.canonicalize()?;

        // 2. Open target process
        let process = ProcessHandle::open(target_pid, PROCESS_ALL_ACCESS)?;

        // 3. Allocate memory in target
        let dll_path_bytes = dll_path_abs.to_str().unwrap().as_bytes();
        let remote_mem = unsafe {
            VirtualAllocEx(
                process.as_handle(),
                None,
                dll_path_bytes.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        // 4. Write DLL path to target memory
        unsafe {
            WriteProcessMemory(
                process.as_handle(),
                remote_mem,
                dll_path_bytes.as_ptr() as *const _,
                dll_path_bytes.len(),
                None,
            )?;
        }

        // 5. Get LoadLibraryA address
        let kernel32 = unsafe { GetModuleHandleA(s!("kernel32.dll"))? };
        let load_library = unsafe { GetProcAddress(kernel32, s!("LoadLibraryA")) };

        // 6. Create remote thread
        let thread = unsafe {
            CreateRemoteThread(
                process.as_handle(),
                None,
                0,
                Some(std::mem::transmute(load_library)),
                Some(remote_mem),
                0,
                None,
            )?
        };

        // 7. Wait for thread completion
        unsafe { WaitForSingleObject(thread, INFINITE) };

        Ok(())
    }
}
```

---

## 2. Manual Mapping

### Overview
The most sophisticated injection technique. Instead of using `LoadLibrary`, manually maps the PE file into the target process and handles imports, relocations, and execution ourselves.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Injector Process                                       │
├─────────────────────────────────────────────────────────┤
│  1. Parse PE headers from DLL file                      │
│     ├─> DOS header (MZ signature)                       │
│     ├─> NT headers (PE signature)                       │
│     ├─> Section headers                                 │
│     └─> Import directory                                │
│                                                          │
│  2. Allocate memory in target at preferred base         │
│     └─> VirtualAllocEx(size = SizeOfImage)              │
│                                                          │
│  3. Map sections into target memory                     │
│     └─> Write each section to correct RVA               │
│                                                          │
│  4. Resolve imports (reconstruct IAT)                   │
│     ├─> For each imported DLL:                          │
│     │   ├─> Load in target if needed                    │
│     │   └─> Resolve each imported function              │
│     └─> Write function addresses to IAT                 │
│                                                          │
│  5. Process base relocations                            │
│     └─> Adjust addresses if not at preferred base       │
│                                                          │
│  6. Set memory protections                              │
│     └─> Make sections executable/writable as needed     │
│                                                          │
│  7. Execute entry point (DllMain)                       │
│     └─> CreateRemoteThread(DllMain, DLL_PROCESS_ATTACH) │
└─────────────────────────────────────────────────────────┘
```

### Advantages
✅ **Stealthier** - DLL doesn't appear in module list
✅ **No LoadLibrary** - Avoids hooks on LoadLibrary
✅ **Custom loading** - Full control over load process
✅ **Bypasses some anti-cheat** - Less obvious than CreateRemoteThread
✅ **Educational** - Deep understanding of PE format

### Disadvantages
❌ **Complex** - Most difficult method to implement correctly
❌ **Error-prone** - Many edge cases (TLS, exceptions, etc.)
❌ **Reliability** - May fail with complex DLLs
❌ **Still detectable** - Memory scanning can find unmapped DLLs

### PE File Format

Understanding the PE format is critical:

```
┌─────────────────────────────────────┐
│  DOS Header (IMAGE_DOS_HEADER)     │  ← Offset 0
│  - e_magic: 0x5A4D ("MZ")          │
│  - e_lfanew: offset to PE header   │
├─────────────────────────────────────┤
│  DOS Stub                           │
├─────────────────────────────────────┤
│  PE Signature (0x00004550)          │  ← Offset e_lfanew
├─────────────────────────────────────┤
│  IMAGE_FILE_HEADER                  │
│  - Machine (x86/x64)                │
│  - NumberOfSections                 │
│  - SizeOfOptionalHeader             │
├─────────────────────────────────────┤
│  IMAGE_OPTIONAL_HEADER              │
│  - AddressOfEntryPoint              │
│  - ImageBase (preferred load addr)  │
│  - SizeOfImage                      │
│  - SizeOfHeaders                    │
│  - DataDirectory[16]                │
│    ├─> [0] Export table             │
│    ├─> [1] Import table             │
│    ├─> [5] Base relocation table    │
│    └─> ...                          │
├─────────────────────────────────────┤
│  Section Headers (array)            │
│  For each section:                  │
│  - Name (.text, .data, .rdata, ...) │
│  - VirtualAddress (RVA)             │
│  - VirtualSize                      │
│  - PointerToRawData (file offset)   │
│  - SizeOfRawData                    │
│  - Characteristics (RWX)            │
├─────────────────────────────────────┤
│  Section Data (.text)               │  ← Code
│  Section Data (.data)               │  ← Initialized data
│  Section Data (.rdata)              │  ← Read-only data
│  Section Data (.reloc)              │  ← Relocations
│  ...                                │
└─────────────────────────────────────┘
```

### Import Resolution Process

```rust
// Pseudocode for import resolution
for import_descriptor in import_directory {
    let dll_name = read_string(import_descriptor.Name);
    let dll_base = load_library_in_target(dll_name);

    let mut thunk = import_descriptor.OriginalFirstThunk;
    let mut iat_entry = import_descriptor.FirstThunk;

    while thunk.is_valid() {
        if thunk.is_ordinal() {
            let ordinal = thunk.get_ordinal();
            let func_addr = get_proc_address_by_ordinal(dll_base, ordinal);
        } else {
            let func_name = read_string(thunk.get_name_rva());
            let func_addr = get_proc_address(dll_base, func_name);
        }

        write_process_memory(target, iat_entry, &func_addr);

        thunk = thunk.next();
        iat_entry = iat_entry.next();
    }
}
```

### Base Relocation Process

When a DLL can't be loaded at its preferred base address, all hardcoded addresses must be adjusted:

```rust
let delta = actual_base - preferred_base;

for relocation_block in relocation_directory {
    let page_rva = relocation_block.VirtualAddress;

    for relocation_entry in relocation_block.entries() {
        let type_ = relocation_entry.type();
        let offset = relocation_entry.offset();
        let address_to_fix = page_rva + offset;

        match type_ {
            IMAGE_REL_BASED_DIR64 => {
                // Read 64-bit value, add delta, write back
                let original = read_u64(actual_base + address_to_fix);
                let relocated = original + delta;
                write_u64(actual_base + address_to_fix, relocated);
            }
            IMAGE_REL_BASED_HIGHLOW => {
                // Read 32-bit value, add delta, write back
                let original = read_u32(actual_base + address_to_fix);
                let relocated = original + delta as u32;
                write_u32(actual_base + address_to_fix, relocated);
            }
            _ => {}
        }
    }
}
```

### Implementation Challenges

1. **TLS Callbacks** - Must execute Thread Local Storage callbacks
2. **Exception Handlers** - SEH/VEH registration
3. **API Sets** - Windows 10+ uses API set schema for imports
4. **Delay-Loaded Imports** - Imports loaded on first use
5. **Dependencies** - DLL may depend on other DLLs

### Detection Vectors
- Memory scanning for suspicious allocations
- Detecting executable memory without backing module
- Analyzing page protections (RWX pages are suspicious)
- Checking module list vs actual loaded code

---

## 3. QueueUserAPC Injection

### Overview
Uses Asynchronous Procedure Calls (APCs) to execute code in the context of an existing thread. Instead of creating a new thread, hijacks an alertable thread.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Injector Process                                       │
├─────────────────────────────────────────────────────────┤
│  1. Enumerate threads in target process                 │
│     └─> CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)     │
│                                                          │
│  2. For each thread in target:                          │
│     ├─> OpenThread(THREAD_SET_CONTEXT)                  │
│     └─> QueueUserAPC(thread, LoadLibraryA, dll_path)    │
│                                                          │
│  3. APC queued to thread's APC queue                    │
│     └─> Will execute when thread enters alertable state │
└─────────────────────────────────────────────────────────┘
                          │
                          ↓
┌─────────────────────────────────────────────────────────┐
│  Target Process Thread                                  │
├─────────────────────────────────────────────────────────┤
│  Thread is running normally...                          │
│  └─> Calls alertable wait function:                     │
│       ├─> SleepEx(time, TRUE)                           │
│       ├─> WaitForSingleObjectEx(..., TRUE)              │
│       └─> MsgWaitForMultipleObjectsEx(..., TRUE)        │
│                                                          │
│  Kernel checks APC queue...                             │
│  └─> Found queued APC!                                  │
│       └─> Execute: LoadLibraryA("C:\\path\\dll.dll")    │
│            └─> DLL loaded and DllMain called            │
└─────────────────────────────────────────────────────────┘
```

### Advantages
✅ **No new threads** - Uses existing threads
✅ **Stealthier** - No CreateRemoteThread signature
✅ **Legitimate API** - APCs are normal Windows mechanism

### Disadvantages
❌ **Timing dependent** - Thread must enter alertable state
❌ **Unreliable** - May never execute if thread never waits
❌ **Multiple threads** - May need to queue to many threads
❌ **Still detectable** - Monitoring tools can hook QueueUserAPC

### Alertable Wait Functions

APCs only execute when a thread calls one of these:
- `SleepEx(duration, TRUE)`
- `WaitForSingleObjectEx(handle, timeout, TRUE)`
- `WaitForMultipleObjectsEx(handles, count, ..., TRUE)`
- `MsgWaitForMultipleObjectsEx(handles, ..., TRUE)`
- `SignalObjectAndWait(..., TRUE)`

**Note:** The last parameter must be `TRUE` (alertable).

### Thread Enumeration

```rust
pub fn enumerate_threads(process_id: u32) -> Result<Vec<u32>> {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
    let mut threads = Vec::new();

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    if Thread32First(snapshot, &mut entry).is_ok() {
        loop {
            if entry.th32OwnerProcessID == process_id {
                threads.push(entry.th32ThreadID);
            }

            if Thread32Next(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }

    Ok(threads)
}
```

### Implementation Strategy

Queue APC to **all threads** to increase success probability:

```rust
pub fn inject_via_apc(pid: u32, dll_path: &Path) -> Result<()> {
    let thread_ids = enumerate_threads(pid)?;
    let load_library = get_load_library_address()?;
    let remote_path = allocate_and_write_path(pid, dll_path)?;

    for thread_id in thread_ids {
        let thread = unsafe {
            OpenThread(THREAD_SET_CONTEXT, false, thread_id)?
        };

        unsafe {
            QueueUserAPC(
                Some(std::mem::transmute(load_library)),
                thread,
                remote_path as usize,
            )?;
        }
    }

    Ok(())
}
```

---

## 4. NtCreateThreadEx Injection

### Overview
Uses the undocumented `NtCreateThreadEx` function from `ntdll.dll`. Similar to CreateRemoteThread but provides more control and is less commonly hooked.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Injector Process                                       │
├─────────────────────────────────────────────────────────┤
│  1. Dynamically resolve NtCreateThreadEx from ntdll     │
│     └─> GetModuleHandle("ntdll.dll")                    │
│         └─> GetProcAddress("NtCreateThreadEx")          │
│                                                          │
│  2. Allocate and write DLL path (same as CRT method)    │
│                                                          │
│  3. Call NtCreateThreadEx with LoadLibraryA             │
│     └─> More parameters than CreateRemoteThread         │
│         └─> Can hide thread from debuggers              │
└─────────────────────────────────────────────────────────┘
```

### Function Signature

```rust
type NtCreateThreadEx = unsafe extern "system" fn(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut std::ffi::c_void,
    process_handle: HANDLE,
    start_routine: *mut std::ffi::c_void,
    argument: *mut std::ffi::c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut std::ffi::c_void,
) -> i32; // NTSTATUS

// Flags
const THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER: u32 = 0x00000004;
```

### Advantages
✅ **Less hooked** - Not as commonly monitored as CreateRemoteThread
✅ **More control** - Additional flags and options
✅ **Hide from debugger** - Can create hidden threads
✅ **Native API** - Lower level than Win32 API

### Disadvantages
❌ **Undocumented** - Function signature may change
❌ **Compatibility** - May not work on future Windows versions
❌ **Complexity** - More parameters to manage

### Dynamic API Resolution

Since `NtCreateThreadEx` is not exported from `windows` crate:

```rust
pub fn get_nt_create_thread_ex() -> Result<NtCreateThreadEx> {
    let ntdll = unsafe { GetModuleHandleA(s!("ntdll.dll"))? };

    let proc_addr = unsafe {
        GetProcAddress(ntdll, s!("NtCreateThreadEx"))
    };

    if proc_addr.is_none() {
        return Err(InjectionError::NtCreateThreadExNotFound);
    }

    Ok(unsafe { std::mem::transmute(proc_addr) })
}
```

---

## Comparison Matrix

| Feature | CreateRemoteThread | Manual Mapping | QueueUserAPC | NtCreateThreadEx |
|---------|-------------------|----------------|---------------|------------------|
| **Complexity** | Low | Very High | Medium | Medium |
| **Reliability** | High | Medium | Medium | High |
| **Stealth Level** | Low | Medium-High | Medium | Medium |
| **Module List** | Visible | Hidden | Visible | Visible |
| **Detection Risk** | High | Medium | Medium | Low-Medium |
| **Windows Support** | All versions | All versions | All versions | Win Vista+ |
| **Implementation Time** | ~4 hours | ~16-24 hours | ~6 hours | ~6 hours |
| **Error Handling** | Simple | Complex | Medium | Medium |
| **Thread Creation** | Yes (new) | Yes (new) | No (existing) | Yes (new) |
| **DllMain Called** | Yes | Yes | Yes | Yes |
| **Educational Value** | Medium | Very High | Medium | High |

## Recommended Usage

**For Learning:**
- Start with **CreateRemoteThread** (simplest)
- Progress to **QueueUserAPC** (intermediate)
- Tackle **Manual Mapping** last (most complex)

**For Stealth:**
- **Manual Mapping** (best stealth, most complex)
- **NtCreateThreadEx** (good stealth, medium complexity)

**For Reliability:**
- **CreateRemoteThread** (most reliable)
- **NtCreateThreadEx** (very reliable)

**For Production:**
- Depends on use case - if stealth required, use Manual Mapping
- If reliability matters more, use CreateRemoteThread
- Consider implementing multiple methods with fallback

## Common Pitfalls

### All Methods
1. **Architecture mismatch** - Always check 32-bit vs 64-bit
2. **Absolute paths** - Relative DLL paths don't work
3. **Privilege requirements** - Need SeDebugPrivilege for many targets
4. **Memory leaks** - Clean up on all code paths (use RAII)
5. **Error handling** - Check every Windows API return value

### CreateRemoteThread Specific
1. **LoadLibrary address** - Must be valid in target process
2. **Thread wait** - Should wait for thread completion to detect errors

### Manual Mapping Specific
1. **Section alignment** - Must respect alignment requirements
2. **Import resolution** - All imports must be resolved correctly
3. **Relocations** - Must apply if not at preferred base
4. **TLS callbacks** - Often forgotten but necessary
5. **Exception handlers** - Required for DLLs using C++ exceptions

### QueueUserAPC Specific
1. **Alertable waits** - Target may never enter alertable state
2. **Multiple threads** - Queue to all threads for reliability
3. **Timing** - May have significant delay before execution

### NtCreateThreadEx Specific
1. **Dynamic resolution** - Function address must be resolved at runtime
2. **Return codes** - Uses NTSTATUS, not bool/HANDLE
3. **Version compatibility** - Test on multiple Windows versions

## References

### Microsoft Documentation
- [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

### Learning Resources
- "Windows Internals" by Mark Russinovich
- "Malware Analyst's Cookbook" by Michael Ligh
- Guided Hacking Forums (DLL injection tutorials)

### Security Research
- Research papers on anti-cheat bypass techniques
- DEFCON presentations on game hacking
- Reverse engineering blogs

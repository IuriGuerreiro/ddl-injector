//! Manual DLL mapping injection.
//!
//! This is the most sophisticated injection technique that manually maps a DLL
//! into the target process without using the Windows loader. The DLL bypasses
//! the PEB module list, making it harder to detect.

use std::path::Path;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject, INFINITE, PROCESS_ACCESS_RIGHTS,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};
use crate::{InjectionError, ProcessHandle};
use crate::memory::{RemoteMemory, write_memory};
use crate::pe::{
    PeFile, map_sections, protect_sections, resolve_imports, process_relocations,
    process_tls_callbacks, register_exception_handlers,
};
use super::InjectionMethod;

/// Manual DLL mapping injector.
///
/// This injector manually maps a DLL into the target process by:
/// 1. Parsing the PE file structure
/// 2. Allocating memory in the target process
/// 3. Mapping sections to the allocated memory
/// 4. Resolving imports from the IAT
/// 5. Processing base relocations
/// 6. Executing TLS callbacks
/// 7. Registering exception handlers (x64)
/// 8. Setting proper memory protections
/// 9. Executing DllMain via shellcode
pub struct ManualMapInjector;

impl InjectionMethod for ManualMapInjector {
    fn inject(&self, process: &ProcessHandle, dll_path: &Path) -> Result<(), InjectionError> {
        log::info!("Starting manual map injection");
        log::info!("DLL: {}", dll_path.display());

        // Step 1: Parse PE file
        log::info!("Step 1: Parsing PE file");
        let pe = PeFile::from_file(dll_path)?;

        log::info!(
            "PE file loaded: {} ({}-bit)",
            dll_path.display(),
            if pe.is_64bit { "64" } else { "32" }
        );

        // Step 2: Allocate remote memory
        log::info!("Step 2: Allocating remote memory");
        let image_size = pe.size_of_image() as usize;
        log::debug!("Image size: {} bytes", image_size);

        let remote_mem = RemoteMemory::allocate(
            process.as_handle(),
            image_size,
            windows::Win32::System::Memory::PAGE_READWRITE,
        )?;

        let base_address = remote_mem.address();
        log::info!("Allocated memory at: 0x{:p}", base_address);

        // Step 3: Map sections
        log::info!("Step 3: Mapping sections");
        unsafe { map_sections(process.as_handle(), &pe, base_address)?; }

        // Step 4: Resolve imports
        log::info!("Step 4: Resolving imports");
        unsafe { resolve_imports(process.as_handle(), &pe, base_address)?; }

        // Step 5: Process relocations
        log::info!("Step 5: Processing relocations");
        unsafe { process_relocations(process.as_handle(), &pe, base_address)?; }

        // Step 6: Process TLS callbacks
        log::info!("Step 6: Processing TLS callbacks");
        unsafe { process_tls_callbacks(process.as_handle(), &pe, base_address)?; }

        // Step 7: Register exception handlers (x64 only)
        log::info!("Step 7: Registering exception handlers");
        unsafe { register_exception_handlers(process.as_handle(), &pe, base_address)?; }

        // Step 8: Protect sections
        log::info!("Step 8: Setting memory protection");
        unsafe { protect_sections(process.as_handle(), &pe, base_address)?; }

        // Step 9: Execute DllMain
        log::info!("Step 9: Executing DllMain");
        let entry_point = pe.entry_point();

        if entry_point == 0 {
            log::warn!("No entry point found, skipping DllMain execution");
            log::info!("Manual map injection completed successfully (no entry point)");
            return Ok(());
        }

        log::debug!("Entry point RVA: 0x{:08X}", entry_point);

        // Create shellcode to call DllMain
        let shellcode = if pe.is_64bit {
            create_loader_shellcode_x64(base_address, entry_point)
        } else {
            create_loader_shellcode_x86(base_address, entry_point)
        };

        log::debug!("Shellcode size: {} bytes", shellcode.len());

        // Allocate memory for shellcode
        let shellcode_mem = RemoteMemory::allocate_executable(
            process.as_handle(),
            shellcode.len(),
        )?;

        log::debug!("Shellcode allocated at: 0x{:p}", shellcode_mem.address());

        // Write shellcode
        write_memory(process.as_handle(), shellcode_mem.address(), &shellcode)?;

        // Execute shellcode
        log::debug!("Creating remote thread for DllMain execution");

        let thread = unsafe {
            CreateRemoteThread(
                process.as_handle(),
                None,
                0,
                Some(std::mem::transmute::<*mut u8, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(shellcode_mem.address())),
                None,
                0,
                None,
            )
            .map_err(|_| InjectionError::CreateThreadFailed(std::io::Error::last_os_error()))?
        };

        log::debug!("Waiting for DllMain to complete");

        unsafe {
            WaitForSingleObject(thread, INFINITE);
        }

        // Check exit code (DllMain return value)
        let mut exit_code = 0u32;
        unsafe {
            GetExitCodeThread(thread, &mut exit_code)
                .map_err(|_| InjectionError::CreateThreadFailed(std::io::Error::last_os_error()))?;
        }

        log::debug!("DllMain exit code: {}", exit_code);

        unsafe {
            let _ = CloseHandle(thread);
        }

        if exit_code == 0 {
            return Err(InjectionError::DllMainFailed);
        }

        log::info!("Manual map injection completed successfully");
        log::info!("DLL base address: 0x{:p}", base_address);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Manual Map"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE
    }
}

/// Create shellcode to call DllMain (x64).
///
/// DllMain signature: BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
/// Calling convention: Microsoft x64 (fastcall) - RCX, RDX, R8, R9, stack
fn create_loader_shellcode_x64(dll_base: *mut u8, entry_point: u32) -> Vec<u8> {
    let dll_main_addr = (dll_base as usize + entry_point as usize) as u64;
    let mut shellcode = Vec::new();

    // sub rsp, 0x28 (shadow space + alignment: 32 bytes + 8 for alignment)
    shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // mov rcx, dll_base (first parameter: hinstDLL)
    shellcode.extend_from_slice(&[0x48, 0xB9]);
    shellcode.extend_from_slice(&(dll_base as u64).to_le_bytes());

    // mov edx, 1 (second parameter: DLL_PROCESS_ATTACH)
    shellcode.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);

    // xor r8, r8 (third parameter: lpvReserved = NULL)
    shellcode.extend_from_slice(&[0x4D, 0x31, 0xC0]);

    // mov rax, dll_main_addr
    shellcode.extend_from_slice(&[0x48, 0xB8]);
    shellcode.extend_from_slice(&dll_main_addr.to_le_bytes());

    // call rax
    shellcode.extend_from_slice(&[0xFF, 0xD0]);

    // add rsp, 0x28
    shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // ret (return value is in eax/rax)
    shellcode.push(0xC3);

    shellcode
}

/// Create shellcode to call DllMain (x86).
///
/// DllMain signature: BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
/// Calling convention: stdcall - parameters pushed right to left, callee cleans up stack
fn create_loader_shellcode_x86(dll_base: *mut u8, entry_point: u32) -> Vec<u8> {
    let dll_main_addr = (dll_base as usize + entry_point as usize) as u32;
    let mut shellcode = Vec::new();

    // push 0 (lpvReserved)
    shellcode.extend_from_slice(&[0x6A, 0x00]);

    // push 1 (DLL_PROCESS_ATTACH)
    shellcode.extend_from_slice(&[0x6A, 0x01]);

    // push dll_base (hinstDLL)
    shellcode.push(0x68);
    shellcode.extend_from_slice(&(dll_base as u32).to_le_bytes());

    // mov eax, dll_main_addr
    shellcode.push(0xB8);
    shellcode.extend_from_slice(&dll_main_addr.to_le_bytes());

    // call eax
    shellcode.extend_from_slice(&[0xFF, 0xD0]);

    // ret 0xC (stdcall cleanup: 3 parameters * 4 bytes = 12 = 0xC)
    shellcode.extend_from_slice(&[0xC2, 0x0C, 0x00]);

    shellcode
}

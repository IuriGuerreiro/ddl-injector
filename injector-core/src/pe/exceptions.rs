//! Exception handler registration (x64 only).

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateRemoteThread, WaitForSingleObject, GetExitCodeThread, INFINITE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use crate::InjectionError;
use crate::memory::{write_memory, RemoteMemory};
use super::parser::PeFile;
use super::headers::*;

/// Register exception handlers for x64 DLLs.
///
/// Calls RtlAddFunctionTable in the target process to register exception handlers.
///
/// # Safety
/// This function dereferences the raw pointer `base_address`.
pub unsafe fn register_exception_handlers(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    if !pe.is_64bit {
        log::debug!("Skipping exception registration (32-bit)");
        return Ok(());
    }

    log::info!("Registering exception handlers (x64)");

    // Get exception directory
    let exception_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        Some(dir) if dir.virtual_address != 0 => dir,
        _ => {
            log::debug!("No exception directory");
            return Ok(());
        }
    };

    log::debug!(
        "Exception directory at RVA: 0x{:08X}, size: {}",
        exception_dir.virtual_address,
        exception_dir.size
    );

    // Get RtlAddFunctionTable address from ntdll.dll
    let ntdll = unsafe {
        GetModuleHandleA(windows::core::s!("ntdll.dll"))
            .map_err(|_| {
                InjectionError::InvalidPeFile("Failed to get ntdll.dll handle".to_string())
            })?
    };

    let rtl_add_function_table = unsafe {
        GetProcAddress(ntdll, windows::core::s!("RtlAddFunctionTable"))
            .ok_or_else(|| {
                InjectionError::InvalidPeFile(
                    "Failed to find RtlAddFunctionTable in ntdll.dll".to_string(),
                )
            })?
    };

    log::debug!(
        "RtlAddFunctionTable address: 0x{:p}",
        rtl_add_function_table as *const ()
    );

    // Calculate exception table address and count
    let exception_table_addr = unsafe { base_address.add(exception_dir.virtual_address as usize) };
    let exception_count = exception_dir.size / 12; // Each RUNTIME_FUNCTION is 12 bytes

    log::debug!(
        "Exception table: address=0x{:p}, count={}",
        exception_table_addr,
        exception_count
    );

    // Create shellcode to call RtlAddFunctionTable
    // BOOLEAN RtlAddFunctionTable(
    //     PRUNTIME_FUNCTION FunctionTable,
    //     DWORD EntryCount,
    //     DWORD64 BaseAddress
    // )
    let shellcode = create_rtl_add_function_table_shellcode(
        rtl_add_function_table as usize,
        exception_table_addr as u64,
        exception_count,
        base_address as u64,
    );

    // Allocate memory for shellcode
    let shellcode_mem = RemoteMemory::allocate_executable(process, shellcode.len())?;

    // Write shellcode
    write_memory(process, shellcode_mem.address(), &shellcode)?;

    // Execute shellcode
    log::debug!("Executing RtlAddFunctionTable shellcode");

    let thread = unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute::<*mut u8, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(shellcode_mem.address())),
            None,
            0,
            None,
        )
        .map_err(|_| InjectionError::CreateThreadFailed(std::io::Error::last_os_error()))?
    };

    // Wait for completion
    unsafe {
        WaitForSingleObject(thread, INFINITE);
    }

    // Check exit code (return value of RtlAddFunctionTable)
    let mut exit_code = 0u32;
    unsafe {
        GetExitCodeThread(thread, &mut exit_code)
            .map_err(|_| {
                InjectionError::InvalidPeFile(
                    "Failed to get RtlAddFunctionTable exit code".to_string(),
                )
            })?;
    }

    if exit_code == 0 {
        log::warn!("RtlAddFunctionTable returned FALSE");
    } else {
        log::info!("Exception handlers registered successfully");
    }

    Ok(())
}

/// Create shellcode to call RtlAddFunctionTable (x64).
///
/// BOOLEAN RtlAddFunctionTable(
///     PRUNTIME_FUNCTION FunctionTable,  // rcx
///     DWORD EntryCount,                 // edx
///     DWORD64 BaseAddress               // r8
/// )
fn create_rtl_add_function_table_shellcode(
    rtl_add_function_table_addr: usize,
    function_table_addr: u64,
    entry_count: u32,
    base_address: u64,
) -> Vec<u8> {
    let mut shellcode = Vec::new();

    // sub rsp, 0x28 (shadow space + alignment)
    shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // mov rcx, function_table_addr (first parameter)
    shellcode.extend_from_slice(&[0x48, 0xB9]);
    shellcode.extend_from_slice(&function_table_addr.to_le_bytes());

    // mov edx, entry_count (second parameter)
    shellcode.push(0xBA);
    shellcode.extend_from_slice(&entry_count.to_le_bytes());

    // mov r8, base_address (third parameter)
    shellcode.extend_from_slice(&[0x49, 0xB8]);
    shellcode.extend_from_slice(&base_address.to_le_bytes());

    // mov rax, rtl_add_function_table_addr
    shellcode.extend_from_slice(&[0x48, 0xB8]);
    shellcode.extend_from_slice(&(rtl_add_function_table_addr as u64).to_le_bytes());

    // call rax
    shellcode.extend_from_slice(&[0xFF, 0xD0]);

    // add rsp, 0x28
    shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // ret (return value is in eax/rax)
    shellcode.push(0xC3);

    shellcode
}

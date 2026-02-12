//! TLS callback processing.

use std::mem;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateRemoteThread, WaitForSingleObject, INFINITE};
use crate::InjectionError;
use crate::memory::{write_memory, RemoteMemory};
use super::parser::PeFile;
use super::headers::*;

/// Process TLS callbacks before DllMain.
///
/// TLS callbacks are executed before DllMain and are used for thread-local storage initialization.
pub fn process_tls_callbacks(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Processing TLS callbacks");

    // Get TLS directory
    let tls_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_TLS) {
        Some(dir) if dir.virtual_address != 0 => dir,
        _ => {
            log::debug!("No TLS directory");
            return Ok(());
        }
    };

    log::debug!(
        "TLS directory at RVA: 0x{:08X}, size: {}",
        tls_dir.virtual_address,
        tls_dir.size
    );

    // Parse TLS directory based on architecture
    if pe.is_64bit {
        process_tls_callbacks_64(process, pe, base_address, tls_dir.virtual_address)?;
    } else {
        process_tls_callbacks_32(process, pe, base_address, tls_dir.virtual_address)?;
    }

    log::info!("TLS callbacks processed successfully");
    Ok(())
}

fn process_tls_callbacks_64(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
    tls_dir_rva: u32,
) -> Result<(), InjectionError> {
    // Read TLS directory
    let tls_data = pe.read_at_rva(tls_dir_rva, mem::size_of::<ImageTlsDirectory64>())?;
    let tls_dir = unsafe { *(tls_data.as_ptr() as *const ImageTlsDirectory64) };

    log::debug!(
        "TLS64: callbacks VA: 0x{:016X}",
        tls_dir.address_of_callbacks
    );

    if tls_dir.address_of_callbacks == 0 {
        log::debug!("No TLS callbacks");
        return Ok(());
    }

    // Convert VA to RVA
    let callbacks_rva = (tls_dir.address_of_callbacks - pe.image_base()) as u32;

    // Read callback array (null-terminated array of function pointers)
    let mut callback_index = 0;
    loop {
        let callback_ptr_rva = callbacks_rva + (callback_index * 8);

        // Read callback function pointer
        let callback_data = pe.read_at_rva(callback_ptr_rva, 8)?;
        let callback_va = u64::from_le_bytes([
            callback_data[0],
            callback_data[1],
            callback_data[2],
            callback_data[3],
            callback_data[4],
            callback_data[5],
            callback_data[6],
            callback_data[7],
        ]);

        // Null pointer marks end of array
        if callback_va == 0 {
            break;
        }

        // Convert VA to RVA
        let callback_rva = (callback_va - pe.image_base()) as u32;
        let callback_addr = unsafe { base_address.add(callback_rva as usize) };

        log::debug!(
            "Executing TLS callback {}: VA=0x{:016X}, RVA=0x{:08X}, Addr=0x{:p}",
            callback_index,
            callback_va,
            callback_rva,
            callback_addr
        );

        // Create shellcode to call the callback
        // TLS callback signature: void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
        let shellcode = create_tls_callback_shellcode_64(base_address, callback_rva);

        // Allocate memory for shellcode
        let shellcode_mem = RemoteMemory::allocate_executable(
            process,
            shellcode.len(),
        )?;

        // Write shellcode
        write_memory(process, shellcode_mem.address(), &shellcode)?;

        // Execute shellcode
        let thread = unsafe {
            CreateRemoteThread(
                process,
                None,
                0,
                Some(std::mem::transmute(shellcode_mem.address())),
                None,
                0,
                None,
            )
            .map_err(|_| InjectionError::CreateThreadFailed(std::io::Error::last_os_error()))?
        };

        // Wait for callback to complete
        unsafe {
            WaitForSingleObject(thread, INFINITE);
        }

        log::debug!("TLS callback {} completed", callback_index);

        callback_index += 1;
    }

    log::debug!("Executed {} TLS callbacks", callback_index);
    Ok(())
}

fn process_tls_callbacks_32(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
    tls_dir_rva: u32,
) -> Result<(), InjectionError> {
    // Read TLS directory
    let tls_data = pe.read_at_rva(tls_dir_rva, mem::size_of::<ImageTlsDirectory32>())?;
    let tls_dir = unsafe { *(tls_data.as_ptr() as *const ImageTlsDirectory32) };

    log::debug!(
        "TLS32: callbacks VA: 0x{:08X}",
        tls_dir.address_of_callbacks
    );

    if tls_dir.address_of_callbacks == 0 {
        log::debug!("No TLS callbacks");
        return Ok(());
    }

    // Convert VA to RVA
    let callbacks_rva = tls_dir.address_of_callbacks - pe.image_base() as u32;

    // Read callback array (null-terminated array of function pointers)
    let mut callback_index = 0;
    loop {
        let callback_ptr_rva = callbacks_rva + (callback_index * 4);

        // Read callback function pointer
        let callback_data = pe.read_at_rva(callback_ptr_rva, 4)?;
        let callback_va = u32::from_le_bytes([
            callback_data[0],
            callback_data[1],
            callback_data[2],
            callback_data[3],
        ]);

        // Null pointer marks end of array
        if callback_va == 0 {
            break;
        }

        // Convert VA to RVA
        let callback_rva = callback_va - pe.image_base() as u32;
        let callback_addr = unsafe { base_address.add(callback_rva as usize) };

        log::debug!(
            "Executing TLS callback {}: VA=0x{:08X}, RVA=0x{:08X}, Addr=0x{:p}",
            callback_index,
            callback_va,
            callback_rva,
            callback_addr
        );

        // Create shellcode to call the callback
        let shellcode = create_tls_callback_shellcode_32(base_address, callback_rva);

        // Allocate memory for shellcode
        let shellcode_mem = RemoteMemory::allocate_executable(
            process,
            shellcode.len(),
        )?;

        // Write shellcode
        write_memory(process, shellcode_mem.address(), &shellcode)?;

        // Execute shellcode
        let thread = unsafe {
            CreateRemoteThread(
                process,
                None,
                0,
                Some(std::mem::transmute(shellcode_mem.address())),
                None,
                0,
                None,
            )
            .map_err(|_| InjectionError::CreateThreadFailed(std::io::Error::last_os_error()))?
        };

        // Wait for callback to complete
        unsafe {
            WaitForSingleObject(thread, INFINITE);
        }

        log::debug!("TLS callback {} completed", callback_index);

        callback_index += 1;
    }

    log::debug!("Executed {} TLS callbacks", callback_index);
    Ok(())
}

/// Create shellcode to call a TLS callback (x64).
///
/// TLS callback signature: void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
/// Reason: DLL_PROCESS_ATTACH (1)
fn create_tls_callback_shellcode_64(dll_base: *mut u8, callback_rva: u32) -> Vec<u8> {
    let callback_addr = (dll_base as usize + callback_rva as usize) as u64;
    let mut shellcode = Vec::new();

    // sub rsp, 0x28 (shadow space + alignment)
    shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // mov rcx, dll_base (first parameter: DllHandle)
    shellcode.extend_from_slice(&[0x48, 0xB9]);
    shellcode.extend_from_slice(&(dll_base as u64).to_le_bytes());

    // mov edx, 1 (second parameter: DLL_PROCESS_ATTACH)
    shellcode.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);

    // xor r8, r8 (third parameter: Reserved = NULL)
    shellcode.extend_from_slice(&[0x4D, 0x31, 0xC0]);

    // mov rax, callback_addr
    shellcode.extend_from_slice(&[0x48, 0xB8]);
    shellcode.extend_from_slice(&callback_addr.to_le_bytes());

    // call rax
    shellcode.extend_from_slice(&[0xFF, 0xD0]);

    // add rsp, 0x28
    shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // ret
    shellcode.push(0xC3);

    shellcode
}

/// Create shellcode to call a TLS callback (x86).
///
/// TLS callback signature: void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
fn create_tls_callback_shellcode_32(dll_base: *mut u8, callback_rva: u32) -> Vec<u8> {
    let callback_addr = (dll_base as usize + callback_rva as usize) as u32;
    let mut shellcode = Vec::new();

    // push 0 (Reserved)
    shellcode.extend_from_slice(&[0x6A, 0x00]);

    // push 1 (DLL_PROCESS_ATTACH)
    shellcode.extend_from_slice(&[0x6A, 0x01]);

    // push dll_base
    shellcode.push(0x68);
    shellcode.extend_from_slice(&(dll_base as u32).to_le_bytes());

    // mov eax, callback_addr
    shellcode.push(0xB8);
    shellcode.extend_from_slice(&callback_addr.to_le_bytes());

    // call eax
    shellcode.extend_from_slice(&[0xFF, 0xD0]);

    // ret 0xC (stdcall cleanup)
    shellcode.extend_from_slice(&[0xC2, 0x0C, 0x00]);

    shellcode
}

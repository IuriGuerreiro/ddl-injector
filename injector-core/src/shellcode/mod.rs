//! Shellcode generation for injection techniques.
//!
//! This module provides utilities for generating position-independent
//! shellcode for various injection methods, particularly thread hijacking.

use crate::error::InjectionError;

/// Generate x64 LoadLibrary shellcode for thread hijacking.
///
/// This shellcode:
/// 1. Preserves all volatile registers
/// 2. Allocates shadow space (required by x64 calling convention)
/// 3. Calls LoadLibraryW with the DLL path
/// 4. Restores registers
/// 5. Jumps back to the original instruction pointer
///
/// # Arguments
/// * `dll_path_addr` - Address of the DLL path string in remote process
/// * `loadlib_addr` - Address of LoadLibraryW function
/// * `return_addr` - Original instruction pointer to return to
#[cfg(target_arch = "x86_64")]
pub fn generate_loadlibrary_shellcode_x64(
    dll_path_addr: usize,
    loadlib_addr: usize,
    return_addr: usize,
) -> Vec<u8> {
    let mut shellcode = Vec::new();

    // Save volatile registers (RAX, RCX, RDX, R8, R9, R10, R11)
    shellcode.extend_from_slice(&[
        0x50, // push rax
        0x51, // push rcx
        0x52, // push rdx
        0x41, 0x50, // push r8
        0x41, 0x51, // push r9
        0x41, 0x52, // push r10
        0x41, 0x53, // push r11
    ]);

    // Allocate shadow space (32 bytes) + alignment
    // sub rsp, 0x28
    shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // mov rcx, dll_path_addr (first parameter for LoadLibraryW)
    shellcode.extend_from_slice(&[0x48, 0xB9]); // movabs rcx
    shellcode.extend_from_slice(&dll_path_addr.to_le_bytes());

    // mov rax, loadlib_addr
    shellcode.extend_from_slice(&[0x48, 0xB8]); // movabs rax
    shellcode.extend_from_slice(&loadlib_addr.to_le_bytes());

    // call rax (call LoadLibraryW)
    shellcode.extend_from_slice(&[0xFF, 0xD0]);

    // Deallocate shadow space
    // add rsp, 0x28
    shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // Restore volatile registers (in reverse order)
    shellcode.extend_from_slice(&[
        0x41, 0x5B, // pop r11
        0x41, 0x5A, // pop r10
        0x41, 0x59, // pop r9
        0x41, 0x58, // pop r8
        0x5A, // pop rdx
        0x59, // pop rcx
        0x58, // pop rax
    ]);

    // Jump to original address
    // mov rax, return_addr
    shellcode.extend_from_slice(&[0x48, 0xB8]); // movabs rax
    shellcode.extend_from_slice(&return_addr.to_le_bytes());

    // jmp rax
    shellcode.extend_from_slice(&[0xFF, 0xE0]);

    shellcode
}

/// Generate x86 LoadLibrary shellcode for thread hijacking.
///
/// This shellcode:
/// 1. Preserves all registers
/// 2. Pushes DLL path as parameter
/// 3. Calls LoadLibraryW
/// 4. Cleans up stack
/// 5. Restores registers
/// 6. Jumps back to original instruction pointer
///
/// # Arguments
/// * `dll_path_addr` - Address of the DLL path string in remote process
/// * `loadlib_addr` - Address of LoadLibraryW function
/// * `return_addr` - Original instruction pointer to return to
#[cfg(target_arch = "x86")]
pub fn generate_loadlibrary_shellcode_x86(
    dll_path_addr: usize,
    loadlib_addr: usize,
    return_addr: usize,
) -> Vec<u8> {
    let mut shellcode = Vec::new();

    // Save all registers
    shellcode.extend_from_slice(&[
        0x60, // pushad (push all general-purpose registers)
        0x9C, // pushfd (push flags)
    ]);

    // Push DLL path address as parameter (stdcall)
    shellcode.extend_from_slice(&[0x68]); // push imm32
    shellcode.extend_from_slice(&(dll_path_addr as u32).to_le_bytes());

    // Call LoadLibraryW
    shellcode.extend_from_slice(&[0xB8]); // mov eax, imm32
    shellcode.extend_from_slice(&(loadlib_addr as u32).to_le_bytes());
    shellcode.extend_from_slice(&[0xFF, 0xD0]); // call eax

    // Restore registers
    shellcode.extend_from_slice(&[
        0x9D, // popfd (restore flags)
        0x61, // popad (restore all general-purpose registers)
    ]);

    // Jump to original address
    shellcode.extend_from_slice(&[0xB8]); // mov eax, imm32
    shellcode.extend_from_slice(&(return_addr as u32).to_le_bytes());
    shellcode.extend_from_slice(&[0xFF, 0xE0]); // jmp eax

    shellcode
}

/// Generate shellcode based on the current architecture.
pub fn generate_loadlibrary_shellcode(
    dll_path_addr: usize,
    loadlib_addr: usize,
    return_addr: usize,
) -> Result<Vec<u8>, InjectionError> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(generate_loadlibrary_shellcode_x64(
            dll_path_addr,
            loadlib_addr,
            return_addr,
        ))
    }

    #[cfg(target_arch = "x86")]
    {
        Ok(generate_loadlibrary_shellcode_x86(
            dll_path_addr,
            loadlib_addr,
            return_addr,
        ))
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        Err(InjectionError::ShellcodeGenerationFailed(
            "Unsupported architecture".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_generate_x64_shellcode() {
        let dll_path_addr = 0x12345678;
        let loadlib_addr = 0x7FFE0000;
        let return_addr = 0xDEADBEEF;

        let shellcode =
            generate_loadlibrary_shellcode_x64(dll_path_addr, loadlib_addr, return_addr);

        // Should not be empty
        assert!(!shellcode.is_empty());

        // Should contain push rax (0x50) at the start
        assert_eq!(shellcode[0], 0x50);

        // Should contain jmp rax (0xFF 0xE0) at the end
        assert_eq!(shellcode[shellcode.len() - 2], 0xFF);
        assert_eq!(shellcode[shellcode.len() - 1], 0xE0);
    }

    #[test]
    #[cfg(target_arch = "x86")]
    fn test_generate_x86_shellcode() {
        let dll_path_addr = 0x12345678;
        let loadlib_addr = 0x7FFE0000;
        let return_addr = 0xDEADBEEF;

        let shellcode =
            generate_loadlibrary_shellcode_x86(dll_path_addr, loadlib_addr, return_addr);

        // Should not be empty
        assert!(!shellcode.is_empty());

        // Should contain pushad (0x60) at the start
        assert_eq!(shellcode[0], 0x60);

        // Should contain jmp eax (0xFF 0xE0) at the end
        assert_eq!(shellcode[shellcode.len() - 2], 0xFF);
        assert_eq!(shellcode[shellcode.len() - 1], 0xE0);
    }

    #[test]
    fn test_generate_shellcode() {
        let dll_path_addr = 0x12345678;
        let loadlib_addr = 0x7FFE0000;
        let return_addr = 0xDEADBEEF;

        let result = generate_loadlibrary_shellcode(dll_path_addr, loadlib_addr, return_addr);

        assert!(result.is_ok());
        let shellcode = result.unwrap();
        assert!(!shellcode.is_empty());
    }
}

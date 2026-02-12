//! PE section mapping and memory protection handling.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
    PAGE_PROTECTION_FLAGS,
};
use crate::InjectionError;
use crate::memory::write_memory;
use super::parser::PeFile;
use super::headers::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};

/// Map PE headers and sections to remote process memory.
///
/// This copies the PE headers and all section data to the allocated memory region
/// in the target process. Sections are mapped to their RVA offsets.
///
/// # Safety
/// This function dereferences the raw pointer `base_address`.
pub unsafe fn map_sections(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Mapping PE sections to remote memory at 0x{:p}", base_address);

    // Step 1: Copy PE headers
    let headers_size = pe.size_of_headers() as usize;
    log::debug!("Copying PE headers ({} bytes)", headers_size);

    write_memory(
        process,
        base_address,
        &pe.data[..headers_size],
    )?;

    // Step 2: Map each section
    for (i, section) in pe.sections.iter().enumerate() {
        let section_name = section.name();
        let dest_addr = unsafe { base_address.add(section.virtual_address as usize) };

        log::debug!(
            "  Mapping section {}: '{}' -> 0x{:p} (RVA: 0x{:08X}, VirtualSize: {}, RawSize: {})",
            i,
            section_name,
            dest_addr,
            section.virtual_address,
            section.virtual_size,
            section.size_of_raw_data
        );

        // Determine how much to copy
        // Use the smaller of virtual_size and size_of_raw_data
        let copy_size = std::cmp::min(section.virtual_size, section.size_of_raw_data) as usize;

        if copy_size == 0 {
            log::debug!("    Skipping empty section '{}'", section_name);
            continue;
        }

        // Get the section data from the file
        let raw_offset = section.pointer_to_raw_data as usize;
        if raw_offset + copy_size > pe.data.len() {
            log::warn!(
                "    Section '{}' data extends beyond file bounds, truncating",
                section_name
            );
            continue;
        }

        let section_data = &pe.data[raw_offset..raw_offset + copy_size];

        // Write section data to remote process
        write_memory(
            process,
            dest_addr,
            section_data,
        )?;

        log::debug!("    Successfully mapped {} bytes", copy_size);
    }

    log::info!("All sections mapped successfully");
    Ok(())
}

/// Set memory protection for each section based on its characteristics.
///
/// This applies the correct memory protection (R/W/X) to each section based on
/// the PE section characteristics flags.
///
/// # Safety
/// This function dereferences the raw pointer `base_address`.
pub unsafe fn protect_sections(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Setting memory protection for sections");

    for (i, section) in pe.sections.iter().enumerate() {
        let section_name = section.name();
        let section_addr = unsafe { base_address.add(section.virtual_address as usize) };
        let section_size = section.virtual_size as usize;

        let protection = section_characteristics_to_protection(section.characteristics);

        log::debug!(
            "  Section {}: '{}' at 0x{:p} ({} bytes) -> {:?}",
            i,
            section_name,
            section_addr,
            section_size,
            protection
        );

        let mut old_protection = PAGE_PROTECTION_FLAGS(0);

        unsafe {
            VirtualProtectEx(
                process,
                section_addr as *const std::ffi::c_void,
                section_size,
                protection,
                &mut old_protection,
            )
            .map_err(|_| {
                InjectionError::MemoryAllocationFailed(std::io::Error::other(
                    format!("Failed to protect section '{}'", section_name)
                ))
            })?;
        }
    }

    log::info!("Memory protection set for all sections");
    Ok(())
}

/// Convert PE section characteristics to Windows memory protection flags.
fn section_characteristics_to_protection(characteristics: u32) -> PAGE_PROTECTION_FLAGS {
    let executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    let readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    let writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    match (executable, readable, writable) {
        (true, _, true) => PAGE_EXECUTE_READWRITE,
        (true, _, false) => PAGE_EXECUTE_READ,
        (false, true, true) | (false, false, true) => PAGE_READWRITE,
        (false, true, false) | (false, false, false) => PAGE_READONLY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_characteristics_to_protection_execute_read() {
        let characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        let protection = section_characteristics_to_protection(characteristics);

        assert_eq!(protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn test_section_characteristics_to_protection_execute_readwrite() {
        let characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        let protection = section_characteristics_to_protection(characteristics);

        assert_eq!(protection, PAGE_EXECUTE_READWRITE);
    }

    #[test]
    fn test_section_characteristics_to_protection_readwrite() {
        let characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        let protection = section_characteristics_to_protection(characteristics);

        assert_eq!(protection, PAGE_READWRITE);
    }

    #[test]
    fn test_section_characteristics_to_protection_readonly() {
        let characteristics = IMAGE_SCN_MEM_READ;
        let protection = section_characteristics_to_protection(characteristics);

        assert_eq!(protection, PAGE_READONLY);
    }

    #[test]
    fn test_section_characteristics_to_protection_write_only() {
        let characteristics = IMAGE_SCN_MEM_WRITE;
        let protection = section_characteristics_to_protection(characteristics);

        // Write-only should map to PAGE_READWRITE
        assert_eq!(protection, PAGE_READWRITE);
    }

    #[test]
    fn test_section_characteristics_to_protection_no_flags() {
        let characteristics = 0;
        let protection = section_characteristics_to_protection(characteristics);

        assert_eq!(protection, PAGE_READONLY);
    }

    #[test]
    fn test_section_characteristics_execute_write() {
        // Execute + Write (without explicit Read)
        let characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
        let protection = section_characteristics_to_protection(characteristics);

        assert_eq!(protection, PAGE_EXECUTE_READWRITE);
    }
}

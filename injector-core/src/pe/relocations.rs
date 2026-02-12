//! PE base relocation processing.

use std::mem;
use windows::Win32::Foundation::HANDLE;
use crate::InjectionError;
use crate::memory::{read_memory_vec, write_memory};
use super::parser::PeFile;
use super::headers::*;

/// Process base relocations for the PE file.
///
/// This adjusts all addresses in the PE file to account for the difference
/// between the preferred base address and the actual load address.
pub fn process_relocations(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Processing base relocations");

    // Get relocation directory
    let reloc_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(dir) if dir.virtual_address != 0 => dir,
        _ => {
            log::debug!("No relocation directory");
            return Ok(());
        }
    };

    log::debug!(
        "Relocation directory at RVA: 0x{:08X}, size: {}",
        reloc_dir.virtual_address,
        reloc_dir.size
    );

    // Calculate delta between preferred and actual base
    let preferred_base = pe.image_base();
    let actual_base = base_address as u64;
    let delta = actual_base.wrapping_sub(preferred_base) as i64;

    log::debug!(
        "Preferred base: 0x{:016X}, Actual base: 0x{:016X}, Delta: 0x{:016X}",
        preferred_base,
        actual_base,
        delta
    );

    // If delta is 0, no relocations needed
    if delta == 0 {
        log::info!("Loaded at preferred base address, no relocations needed");
        return Ok(());
    }

    // Process each relocation block
    let mut offset = 0;
    while offset < reloc_dir.size as usize {
        let block_rva = reloc_dir.virtual_address + offset as u32;

        // Read relocation block header
        let block_data = pe.read_at_rva(block_rva, mem::size_of::<ImageBaseRelocation>())?;
        let block = unsafe { *(block_data.as_ptr() as *const ImageBaseRelocation) };

        if block.size_of_block == 0 {
            break;
        }

        log::debug!(
            "Processing relocation block at RVA: 0x{:08X}, Page RVA: 0x{:08X}, Size: {}",
            block_rva,
            block.virtual_address,
            block.size_of_block
        );

        // Calculate number of entries
        let header_size = mem::size_of::<ImageBaseRelocation>();
        let entries_size = block.size_of_block as usize - header_size;
        let num_entries = entries_size / 2; // Each entry is 2 bytes

        // Process each relocation entry
        for i in 0..num_entries {
            let entry_rva = block_rva + header_size as u32 + (i * 2) as u32;
            let entry_data = pe.read_at_rva(entry_rva, 2)?;
            let entry = u16::from_le_bytes([entry_data[0], entry_data[1]]);

            // Extract type (high 4 bits) and offset (low 12 bits)
            let reloc_type = entry >> 12;
            let reloc_offset = entry & 0x0FFF;

            // Calculate target RVA
            let target_rva = block.virtual_address + reloc_offset as u32;
            let target_address = unsafe { base_address.add(target_rva as usize) };

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Skip, used for padding
                    continue;
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    // 32-bit relocation
                    log::trace!(
                        "  HIGHLOW relocation at RVA: 0x{:08X} (address: 0x{:p})",
                        target_rva,
                        target_address
                    );

                    // Read current value
                    let current_bytes = read_memory_vec(process, target_address, 4)?;
                    let current_value =
                        u32::from_le_bytes([current_bytes[0], current_bytes[1], current_bytes[2], current_bytes[3]]);

                    // Apply relocation
                    let new_value = (current_value as i64).wrapping_add(delta) as u32;

                    // Write new value
                    write_memory(process, target_address, &new_value.to_le_bytes())?;
                }
                IMAGE_REL_BASED_DIR64 => {
                    // 64-bit relocation
                    log::trace!(
                        "  DIR64 relocation at RVA: 0x{:08X} (address: 0x{:p})",
                        target_rva,
                        target_address
                    );

                    // Read current value
                    let current_bytes = read_memory_vec(process, target_address, 8)?;
                    let current_value = u64::from_le_bytes([
                        current_bytes[0],
                        current_bytes[1],
                        current_bytes[2],
                        current_bytes[3],
                        current_bytes[4],
                        current_bytes[5],
                        current_bytes[6],
                        current_bytes[7],
                    ]);

                    // Apply relocation
                    let new_value = (current_value as i64).wrapping_add(delta) as u64;

                    // Write new value
                    write_memory(process, target_address, &new_value.to_le_bytes())?;
                }
                _ => {
                    return Err(InjectionError::InvalidRelocationType(reloc_type));
                }
            }
        }

        offset += block.size_of_block as usize;
    }

    log::info!("Base relocations processed successfully");
    Ok(())
}

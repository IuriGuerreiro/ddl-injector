//! PE export table parsing.

use super::headers::*;
use super::parser::PeFile;
use crate::InjectionError;
use std::mem;

/// Information about a single exported function.
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// Function name (empty string if export by ordinal only)
    pub name: String,
    /// Export ordinal
    pub ordinal: u16,
    /// RVA of the function
    pub rva: u32,
    /// Whether this is a forwarded export
    pub is_forwarded: bool,
    /// Forward name (e.g., "NTDLL.RtlAllocateHeap") if forwarded
    pub forward_name: Option<String>,
}

/// Complete export table information.
#[derive(Debug, Clone)]
pub struct ExportTable {
    /// Name of the exporting DLL
    pub dll_name: String,
    /// List of all exports
    pub exports: Vec<ExportInfo>,
}

/// Parse the export table from a PE file.
///
/// Reads the export directory and extracts all exported functions with their
/// names, ordinals, and addresses. Handles both named exports and ordinal-only
/// exports, as well as forwarded exports.
///
/// # Arguments
/// * `pe` - The parsed PE file
///
/// # Returns
/// * `Ok(ExportTable)` - Successfully parsed export table
/// * `Err(InjectionError::ExportTableNotFound)` - No export directory found
/// * `Err(InjectionError::InvalidPeFile)` - Malformed export data
pub fn parse_exports(pe: &PeFile) -> Result<ExportTable, InjectionError> {
    log::debug!("Parsing export table");

    // Get export directory
    let export_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
        Some(dir) if dir.virtual_address != 0 && dir.size != 0 => dir,
        _ => {
            return Err(InjectionError::ExportTableNotFound(
                "No export directory".to_string(),
            ));
        }
    };

    log::debug!(
        "Export directory at RVA: 0x{:08X}, size: {}",
        export_dir.virtual_address,
        export_dir.size
    );

    // Read export directory structure
    let export_dir_size = mem::size_of::<ImageExportDirectory>();
    let export_dir_data = pe.read_at_rva(export_dir.virtual_address, export_dir_size)?;
    let export_directory =
        unsafe { *(export_dir_data.as_ptr() as *const ImageExportDirectory) };

    log::debug!(
        "Export directory: functions={}, names={}, base={}",
        export_directory.number_of_functions,
        export_directory.number_of_names,
        export_directory.base
    );

    // Read DLL name
    let dll_name = pe.read_string_at_rva(export_directory.name)?;
    log::debug!("Exporting DLL: {}", dll_name);

    // Calculate the range of the export directory for forwarding detection
    let export_dir_start = export_dir.virtual_address;
    let export_dir_end = export_dir_start + export_dir.size;

    // Read Export Address Table (array of RVAs)
    let eat_size = (export_directory.number_of_functions * 4) as usize;
    let eat_data = pe.read_at_rva(export_directory.address_of_functions, eat_size)?;
    let eat: Vec<u32> = (0..export_directory.number_of_functions)
        .map(|i| {
            let offset = (i * 4) as usize;
            u32::from_le_bytes([
                eat_data[offset],
                eat_data[offset + 1],
                eat_data[offset + 2],
                eat_data[offset + 3],
            ])
        })
        .collect();

    // Read Export Name Pointer Table (array of RVAs to names)
    let name_ptr_size = (export_directory.number_of_names * 4) as usize;
    let name_ptr_data = pe.read_at_rva(export_directory.address_of_names, name_ptr_size)?;
    let name_ptrs: Vec<u32> = (0..export_directory.number_of_names)
        .map(|i| {
            let offset = (i * 4) as usize;
            u32::from_le_bytes([
                name_ptr_data[offset],
                name_ptr_data[offset + 1],
                name_ptr_data[offset + 2],
                name_ptr_data[offset + 3],
            ])
        })
        .collect();

    // Read Export Ordinal Table (array of u16 indices into EAT)
    let ordinal_size = (export_directory.number_of_names * 2) as usize;
    let ordinal_data = pe.read_at_rva(export_directory.address_of_name_ordinals, ordinal_size)?;
    let ordinals: Vec<u16> = (0..export_directory.number_of_names)
        .map(|i| {
            let offset = (i * 2) as usize;
            u16::from_le_bytes([ordinal_data[offset], ordinal_data[offset + 1]])
        })
        .collect();

    log::debug!(
        "Read {} EAT entries, {} names, {} ordinals",
        eat.len(),
        name_ptrs.len(),
        ordinals.len()
    );

    // Build export list
    let mut exports = Vec::new();

    // Create a map of ordinal index -> name for named exports
    let mut ordinal_to_name = std::collections::HashMap::new();
    for (name_idx, &ordinal_idx) in ordinals.iter().enumerate() {
        let name_rva = name_ptrs[name_idx];
        let name = pe.read_string_at_rva(name_rva)?;
        ordinal_to_name.insert(ordinal_idx as usize, name);
    }

    // Process all functions in the EAT
    for (eat_idx, &function_rva) in eat.iter().enumerate() {
        // Skip null entries (holes in export table)
        if function_rva == 0 {
            continue;
        }

        // Calculate actual ordinal (base + index)
        let ordinal = (export_directory.base + eat_idx as u32) as u16;

        // Get name if this export has one
        let name = ordinal_to_name.get(&eat_idx).cloned().unwrap_or_default();

        // Check if this is a forwarded export
        // Forwarded exports have RVA pointing inside the export directory
        let is_forwarded = function_rva >= export_dir_start && function_rva < export_dir_end;

        let forward_name = if is_forwarded {
            // Read forwarded name (e.g., "NTDLL.RtlAllocateHeap")
            match pe.read_string_at_rva(function_rva) {
                Ok(fwd_name) => {
                    log::debug!("  Export '{}' forwarded to: {}", name, fwd_name);
                    Some(fwd_name)
                }
                Err(_) => None,
            }
        } else {
            None
        };

        exports.push(ExportInfo {
            name,
            ordinal,
            rva: function_rva,
            is_forwarded,
            forward_name,
        });
    }

    log::info!(
        "Parsed {} exports from {}",
        exports.len(),
        dll_name
    );

    Ok(ExportTable { dll_name, exports })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_version_dll() {
        // Test parsing version.dll exports
        let system32 = std::env::var("SystemRoot")
            .unwrap_or_else(|_| "C:\\Windows".to_string());
        let version_dll_path = PathBuf::from(system32)
            .join("System32")
            .join("version.dll");

        if !version_dll_path.exists() {
            println!("Skipping test: version.dll not found");
            return;
        }

        let pe = PeFile::from_file(&version_dll_path)
            .expect("Failed to parse version.dll");

        let exports = parse_exports(&pe).expect("Failed to parse exports");

        assert_eq!(exports.dll_name.to_lowercase(), "version.dll");
        assert!(exports.exports.len() > 0);

        // version.dll should have these common exports
        let export_names: Vec<&str> = exports
            .exports
            .iter()
            .map(|e| e.name.as_str())
            .collect();

        assert!(export_names.contains(&"GetFileVersionInfoA"));
        assert!(export_names.contains(&"GetFileVersionInfoW"));
        assert!(export_names.contains(&"GetFileVersionInfoSizeA"));
        assert!(export_names.contains(&"GetFileVersionInfoSizeW"));

        println!("Parsed {} exports from version.dll", exports.exports.len());
        for export in &exports.exports {
            println!(
                "  {} (ordinal {}, RVA 0x{:08X}{})",
                export.name,
                export.ordinal,
                export.rva,
                if export.is_forwarded {
                    format!(
                        ", forwarded to {}",
                        export.forward_name.as_ref().unwrap_or(&"?".to_string())
                    )
                } else {
                    "".to_string()
                }
            );
        }
    }

    #[test]
    fn test_parse_kernel32_dll() {
        let system32 = std::env::var("SystemRoot")
            .unwrap_or_else(|_| "C:\\Windows".to_string());
        let kernel32_path = PathBuf::from(system32)
            .join("System32")
            .join("kernel32.dll");

        if !kernel32_path.exists() {
            println!("Skipping test: kernel32.dll not found");
            return;
        }

        let pe = PeFile::from_file(&kernel32_path)
            .expect("Failed to parse kernel32.dll");

        let exports = parse_exports(&pe).expect("Failed to parse exports");

        assert_eq!(exports.dll_name.to_lowercase(), "kernel32.dll");
        assert!(exports.exports.len() > 1000); // kernel32 has many exports

        println!(
            "Parsed {} exports from kernel32.dll",
            exports.exports.len()
        );
    }

    #[test]
    fn test_no_export_directory() {
        // Create a minimal PE with no export directory
        // Most executables don't have exports, only DLLs do
        let system32 = std::env::var("SystemRoot")
            .unwrap_or_else(|_| "C:\\Windows".to_string());
        let notepad_path = PathBuf::from(system32)
            .join("System32")
            .join("notepad.exe");

        if !notepad_path.exists() {
            println!("Skipping test: notepad.exe not found");
            return;
        }

        let pe = PeFile::from_file(&notepad_path)
            .expect("Failed to parse notepad.exe");

        let result = parse_exports(&pe);

        // notepad.exe likely has no exports
        if result.is_err() {
            match result {
                Err(InjectionError::ExportTableNotFound(_)) => {
                    println!("As expected, notepad.exe has no exports");
                }
                _ => panic!("Expected ExportTableNotFound error"),
            }
        }
    }
}

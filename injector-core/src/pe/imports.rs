//! PE import table resolution.

use super::headers::*;
use super::parser::PeFile;
use crate::memory::write_memory;
use crate::InjectionError;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleA, GetProcAddress, LoadLibraryExA, LOAD_LIBRARY_AS_DATAFILE,
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
};

/// Resolve all imports in the PE file and write function pointers to IAT.
///
/// This processes the import directory, loads each DLL, resolves imports by name
/// or ordinal, and writes the function addresses to the Import Address Table (IAT)
/// in the remote process.
///
/// # Safety
/// This function dereferences the raw pointer `base_address`.
pub unsafe fn resolve_imports(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Resolving imports");

    // Get import directory
    let import_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(dir) if dir.virtual_address != 0 => dir,
        _ => {
            log::debug!("No import directory");
            return Ok(());
        }
    };

    log::debug!(
        "Import directory at RVA: 0x{:08X}, size: {}",
        import_dir.virtual_address,
        import_dir.size
    );

    // Calculate number of import descriptors
    let descriptor_size = mem::size_of::<ImageImportDescriptor>();
    let max_descriptors = import_dir.size as usize / descriptor_size;

    // Process each import descriptor
    for i in 0..max_descriptors {
        let descriptor_rva = import_dir.virtual_address + (i * descriptor_size) as u32;

        // Read import descriptor from PE file
        let descriptor_data = pe.read_at_rva(descriptor_rva, descriptor_size)?;
        let descriptor = unsafe { *(descriptor_data.as_ptr() as *const ImageImportDescriptor) };

        // Null descriptor marks end of import table
        if descriptor.is_null() {
            log::debug!("End of import table at descriptor {}", i);
            break;
        }

        // Get DLL name
        let dll_name = pe.read_string_at_rva(descriptor.name)?;
        log::debug!("Processing imports from: {}", dll_name);

        // Create null-terminated string for Windows API
        let dll_name_cstr = std::ffi::CString::new(dll_name.as_str())
            .map_err(|_| InjectionError::ImportModuleNotFound(dll_name.clone()))?;

        // Load the DLL in our process to get function addresses
        // Try GetModuleHandleA first, if it fails, use LoadLibraryExA
        let dll_handle = unsafe {
            match GetModuleHandleA(PCSTR::from_raw(dll_name_cstr.as_ptr() as *const u8)) {
                Ok(handle) => {
                    log::debug!("  DLL already loaded: {}", dll_name);
                    handle
                }
                Err(_) => {
                    // Use LoadLibraryExA with LOAD_LIBRARY_AS_DATAFILE to map the DLL without executing its code.
                    // Also use LOAD_LIBRARY_SEARCH_DEFAULT_DIRS to find system DLLs and local dependencies.
                    match LoadLibraryExA(
                        PCSTR::from_raw(dll_name_cstr.as_ptr() as *const u8),
                        None,
                        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                    ) {
                        Ok(handle) => {
                            log::debug!("  Successfully mapped DLL as datafile: {}", dll_name);
                            handle
                        }
                        Err(e) => {
                            log::error!("  Failed to load DLL '{}': {}", dll_name, e);
                            return Err(InjectionError::ImportModuleNotFound(format!(
                                "{} (LoadLibraryExA failed: {})",
                                dll_name, e
                            )));
                        }
                    }
                }
            }
        };

        // Determine which thunk array to use
        // Prefer OriginalFirstThunk (INT), fall back to FirstThunk (IAT)
        let thunk_rva = if descriptor.original_first_thunk != 0 {
            descriptor.original_first_thunk
        } else {
            descriptor.first_thunk
        };

        let iat_rva = descriptor.first_thunk;

        log::debug!("  INT RVA: 0x{:08X}, IAT RVA: 0x{:08X}", thunk_rva, iat_rva);

        // Process thunks
        let thunk_size = if pe.is_64bit { 8 } else { 4 };
        let mut thunk_offset = 0;

        loop {
            let current_thunk_rva = thunk_rva + thunk_offset;
            let current_iat_rva = iat_rva + thunk_offset;

            // Read thunk value
            let thunk_value = if pe.is_64bit {
                let data = pe.read_at_rva(current_thunk_rva, 8)?;
                u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ])
            } else {
                let data = pe.read_at_rva(current_thunk_rva, 4)?;
                u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64
            };

            // Null thunk marks end of imports for this DLL
            if thunk_value == 0 {
                break;
            }

            // Determine if import is by ordinal or by name
            let is_ordinal = if pe.is_64bit {
                (thunk_value & IMAGE_ORDINAL_FLAG64) != 0
            } else {
                (thunk_value & (IMAGE_ORDINAL_FLAG32 as u64)) != 0
            };

            let function_address = if is_ordinal {
                // Import by ordinal
                let ordinal = (thunk_value & 0xFFFF) as u16;
                log::debug!("    Resolving import by ordinal: {}", ordinal);

                unsafe {
                    GetProcAddress(dll_handle, PCSTR::from_raw(ordinal as usize as *const u8))
                        .ok_or_else(|| {
                            InjectionError::ImportFunctionNotFound(
                                format!("ordinal {}", ordinal),
                                dll_name.clone(),
                            )
                        })?
                }
            } else {
                // Import by name
                let import_by_name_rva = thunk_value as u32;

                // Read hint (2 bytes) - we don't use it but need to skip it
                let name_offset = pe.rva_to_offset(import_by_name_rva).ok_or_else(|| {
                    InjectionError::InvalidPeFile(format!(
                        "Invalid RVA for import name: 0x{:08X}",
                        import_by_name_rva
                    ))
                })? + 2; // Skip hint

                // Read function name
                let name_bytes = &pe.data[name_offset..];
                let name_len = name_bytes.iter().position(|&c| c == 0).ok_or_else(|| {
                    InjectionError::InvalidPeFile("Unterminated import name".to_string())
                })?;

                let function_name = String::from_utf8_lossy(&name_bytes[..name_len]);
                log::debug!("    Resolving import by name: {}", function_name);

                unsafe {
                    GetProcAddress(dll_handle, PCSTR::from_raw(name_bytes.as_ptr())).ok_or_else(
                        || {
                            InjectionError::ImportFunctionNotFound(
                                function_name.to_string(),
                                dll_name.clone(),
                            )
                        },
                    )?
                }
            };

            // Write function address to IAT in remote process
            let iat_address = unsafe { base_address.add(current_iat_rva as usize) };

            // Write function address to IAT (usize ensures correct pointer width)
            let func_addr = function_address as usize;
            write_memory(process, iat_address, &func_addr.to_le_bytes())?;

            thunk_offset += thunk_size;
        }

        log::debug!("  Resolved all imports from {}", dll_name);
    }

    log::info!("All imports resolved successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dll_path() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("target")
            .join("release")
            .join("test_dll.dll")
    }

    #[test]
    fn test_import_directory_exists() {
        let dll_path = test_dll_path();
        if !dll_path.exists() {
            return;
        }

        let pe = crate::pe::parser::PeFile::from_file(&dll_path).expect("Failed to parse test DLL");

        let import_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        assert!(import_dir.is_some());

        if let Some(dir) = import_dir {
            assert!(dir.virtual_address > 0);
            assert!(dir.size > 0);
        }
    }

    #[test]
    fn test_ordinal_flags() {
        assert_eq!(IMAGE_ORDINAL_FLAG32, 0x80000000);
        assert_eq!(IMAGE_ORDINAL_FLAG64, 0x8000000000000000);
    }

    #[test]
    fn test_ordinal_detection_32bit() {
        let thunk_value: u32 = IMAGE_ORDINAL_FLAG32 | 42; // Ordinal 42
        let is_ordinal = (thunk_value & IMAGE_ORDINAL_FLAG32) != 0;

        assert!(is_ordinal);

        let ordinal = (thunk_value & 0xFFFF) as u16;
        assert_eq!(ordinal, 42);
    }

    #[test]
    fn test_ordinal_detection_64bit() {
        let thunk_value: u64 = IMAGE_ORDINAL_FLAG64 | 100; // Ordinal 100
        let is_ordinal = (thunk_value & IMAGE_ORDINAL_FLAG64) != 0;

        assert!(is_ordinal);

        let ordinal = (thunk_value & 0xFFFF) as u16;
        assert_eq!(ordinal, 100);
    }
}

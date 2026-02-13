//! PE file format header structures and constants.

use std::fmt;

// PE signature constants
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

// Machine types
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c; // x86
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x64

// Data directory indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// Section characteristics
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// Base relocation types
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3; // 32-bit relocation
pub const IMAGE_REL_BASED_DIR64: u16 = 10; // 64-bit relocation

// Import descriptor constants
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// DOS header (at file offset 0)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,      // Magic number "MZ"
    pub e_cblp: u16,       // Bytes on last page of file
    pub e_cp: u16,         // Pages in file
    pub e_crlc: u16,       // Relocations
    pub e_cparhdr: u16,    // Size of header in paragraphs
    pub e_minalloc: u16,   // Minimum extra paragraphs needed
    pub e_maxalloc: u16,   // Maximum extra paragraphs needed
    pub e_ss: u16,         // Initial (relative) SS value
    pub e_sp: u16,         // Initial SP value
    pub e_csum: u16,       // Checksum
    pub e_ip: u16,         // Initial IP value
    pub e_cs: u16,         // Initial (relative) CS value
    pub e_lfarlc: u16,     // File address of relocation table
    pub e_ovno: u16,       // Overlay number
    pub e_res: [u16; 4],   // Reserved words
    pub e_oemid: u16,      // OEM identifier
    pub e_oeminfo: u16,    // OEM information
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: i32,     // File address of new exe header
}

impl ImageDosHeader {
    /// Validate the DOS header magic number.
    pub fn validate(&self) -> Result<(), crate::InjectionError> {
        if self.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(crate::InjectionError::InvalidDosHeader(self.e_magic));
        }
        Ok(())
    }
}

/// COFF File Header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,                 // Machine type
    pub number_of_sections: u16,      // Number of sections
    pub time_date_stamp: u32,         // Time date stamp
    pub pointer_to_symbol_table: u32, // Pointer to symbol table
    pub number_of_symbols: u32,       // Number of symbols
    pub size_of_optional_header: u16, // Size of optional header
    pub characteristics: u16,         // Characteristics
}

/// Data directory entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32, // RVA of the data
    pub size: u32,            // Size of the data
}

/// Optional Header (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

/// Optional Header (32-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

/// Section Header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl ImageSectionHeader {
    /// Get the section name as a string.
    pub fn name(&self) -> String {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..len]).to_string()
    }
}

impl fmt::Debug for ImageSectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageSectionHeader")
            .field("name", &self.name())
            .field("virtual_size", &self.virtual_size)
            .field("virtual_address", &self.virtual_address)
            .field("size_of_raw_data", &self.size_of_raw_data)
            .field("pointer_to_raw_data", &self.pointer_to_raw_data)
            .field(
                "characteristics",
                &format_args!("0x{:08X}", self.characteristics),
            )
            .finish()
    }
}

/// Import Descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32, // RVA to original unbound IAT (INT)
    pub time_date_stamp: u32,      // 0 if not bound
    pub forwarder_chain: u32,      // -1 if no forwarders
    pub name: u32,                 // RVA of imported DLL name
    pub first_thunk: u32,          // RVA to IAT
}

impl ImageImportDescriptor {
    /// Check if this is a null descriptor (end of import table).
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name == 0
            && self.first_thunk == 0
    }
}

/// Import by name structure
#[repr(C, packed(2))]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportByName {
    pub hint: u16,
    // Followed by null-terminated ASCII name
}

/// Base Relocation Block
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32, // RVA of the relocation block
    pub size_of_block: u32,   // Size of this block including header
}

/// TLS Directory (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64, // Array of PIMAGE_TLS_CALLBACK
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

/// TLS Directory (32-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory32 {
    pub start_address_of_raw_data: u32,
    pub end_address_of_raw_data: u32,
    pub address_of_index: u32,
    pub address_of_callbacks: u32, // Array of PIMAGE_TLS_CALLBACK
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

/// Export Directory
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,                    // RVA to DLL name
    pub base: u32,                    // Starting ordinal
    pub number_of_functions: u32,     // Number of entries in EAT
    pub number_of_names: u32,         // Number of entries in name pointer table
    pub address_of_functions: u32,    // RVA to Export Address Table (EAT)
    pub address_of_names: u32,        // RVA to Export Name Pointer Table
    pub address_of_name_ordinals: u32, // RVA to Export Ordinal Table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_header_validate_valid() {
        let header = ImageDosHeader {
            e_magic: IMAGE_DOS_SIGNATURE,
            e_cblp: 0,
            e_cp: 0,
            e_crlc: 0,
            e_cparhdr: 0,
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 0x100,
        };

        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_dos_header_validate_invalid() {
        let header = ImageDosHeader {
            e_magic: 0x0000, // Invalid magic
            e_cblp: 0,
            e_cp: 0,
            e_crlc: 0,
            e_cparhdr: 0,
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 0x100,
        };

        assert!(header.validate().is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(IMAGE_DOS_SIGNATURE, 0x5A4D); // "MZ"
        assert_eq!(IMAGE_NT_SIGNATURE, 0x00004550); // "PE\0\0"
        assert_eq!(IMAGE_FILE_MACHINE_I386, 0x014c);
        assert_eq!(IMAGE_FILE_MACHINE_AMD64, 0x8664);
    }

    #[test]
    fn test_section_characteristics_constants() {
        assert_eq!(IMAGE_SCN_MEM_EXECUTE, 0x20000000);
        assert_eq!(IMAGE_SCN_MEM_READ, 0x40000000);
        assert_eq!(IMAGE_SCN_MEM_WRITE, 0x80000000);
    }

    #[test]
    fn test_relocation_type_constants() {
        assert_eq!(IMAGE_REL_BASED_ABSOLUTE, 0);
        assert_eq!(IMAGE_REL_BASED_HIGHLOW, 3);
        assert_eq!(IMAGE_REL_BASED_DIR64, 10);
    }

    #[test]
    fn test_section_header_name() {
        let mut section = ImageSectionHeader {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };

        // Test with ".text" section name
        section.name[0] = b'.';
        section.name[1] = b't';
        section.name[2] = b'e';
        section.name[3] = b'x';
        section.name[4] = b't';

        let name = section.name();
        assert_eq!(name, ".text");
    }

    #[test]
    fn test_section_header_name_full_length() {
        let mut section = ImageSectionHeader {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };

        // Test with full 8-character name (no null terminator)
        section.name = *b"longsect";

        let name = section.name();
        assert_eq!(name, "longsect");
    }

    #[test]
    fn test_import_descriptor_is_null() {
        let null_desc = ImageImportDescriptor {
            original_first_thunk: 0,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name: 0,
            first_thunk: 0,
        };

        assert!(null_desc.is_null());

        let non_null_desc = ImageImportDescriptor {
            original_first_thunk: 0x1000,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name: 0x2000,
            first_thunk: 0x3000,
        };

        assert!(!non_null_desc.is_null());
    }

    #[test]
    fn test_data_directory_indices() {
        assert_eq!(IMAGE_DIRECTORY_ENTRY_EXPORT, 0);
        assert_eq!(IMAGE_DIRECTORY_ENTRY_IMPORT, 1);
        assert_eq!(IMAGE_DIRECTORY_ENTRY_RESOURCE, 2);
        assert_eq!(IMAGE_DIRECTORY_ENTRY_EXCEPTION, 3);
        assert_eq!(IMAGE_DIRECTORY_ENTRY_BASERELOC, 5);
        assert_eq!(IMAGE_DIRECTORY_ENTRY_TLS, 9);
    }
}

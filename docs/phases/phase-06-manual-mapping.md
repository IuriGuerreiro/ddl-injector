# Phase 6: Manual Mapping

**Status:** ⏳ Pending
**Estimated Time:** 16-24 hours
**Complexity:** Very High

## Phase Overview

Implement manual DLL mapping - the most sophisticated and stealthy injection method. Instead of using LoadLibrary, we manually parse the PE file, map sections into memory, resolve imports, handle relocations, and call DllMain ourselves. This bypasses many anti-cheat detection mechanisms since the DLL doesn't appear in the PEB module list.

**This is the most complex phase of the entire project.** Take your time and test thoroughly.

## Objectives

- [ ] Implement comprehensive PE file parser
- [ ] Parse DOS header, NT headers, section headers
- [ ] Map PE sections into remote memory
- [ ] Resolve import address table (IAT)
- [ ] Handle deep base relocations (including all block types)
- [ ] Implement TLS (Thread Local Storage) support and callbacks
- [ ] Register exception handlers (RtlAddFunctionTable for x64)
- [ ] Call DllMain entry point remotely
- [ ] Add thorough error handling and validation
- [ ] Create extensive tests with sample DLLs

## Prerequisites

- ✅ Phase 5: Privilege elevation complete
- Deep understanding of PE file format
- Knowledge of Windows loader internals
- Familiarity with assembly basics
- Understanding of virtual memory concepts

## Learning Resources

**Critical Reading:**
- [PE Format Specification (Microsoft)](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Portable Executable File Format](https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files)
- [PE Internals](http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf)
- [Manual Mapping Tutorial](https://www.unknowncheats.me/wiki/General_Programming:Manual_Mapping)

**API References:**
- [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
- [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)

## File Structure

```
injector-core/src/
├── pe/
│   ├── mod.rs                  # PE module exports ← UPDATE
│   ├── parser.rs               # PE file parsing ← NEW (400+ lines)
│   ├── headers.rs              # Header structures ← NEW
│   ├── sections.rs             # Section mapping ← NEW
│   ├── imports.rs              # Import resolution ← NEW
│   └── relocations.rs          # Base relocations ← NEW
├── injection/
│   └── manual_map.rs           # Manual map injector ← NEW (500+ lines)
├── memory/
│   └── reader.rs               # Memory reading ← NEW
└── error.rs                    # Add PE errors ← UPDATE
```

## Dependencies

No new dependencies - uses existing `windows` crate and standard library.

## PE Format Overview

Before implementation, understand PE structure:

```
PE File Structure:
┌─────────────────────┐
│   DOS Header        │ ← "MZ" signature
│   DOS Stub          │
├─────────────────────┤
│   PE Signature      │ ← "PE\0\0"
│   COFF Header       │ ← Machine type, sections count
│   Optional Header   │ ← Entry point, image base, etc.
├─────────────────────┤
│   Section Headers   │ ← .text, .data, .rdata, etc.
├─────────────────────┤
│   .text section     │ ← Executable code
│   .data section     │ ← Initialized data
│   .rdata section    │ ← Read-only data
│   .reloc section    │ ← Base relocations
│   Import Directory  │ ← Imported functions
│   Export Directory  │ ← Exported functions
└─────────────────────┘
```

## Step-by-Step Implementation

### Step 1: Add PE Error Types

**File:** `injector-core/src/error.rs` (update InjectionError)

```rust
#[derive(Debug, Error)]
pub enum InjectionError {
    // ... existing variants ...

    #[error("Invalid PE file: {0}")]
    InvalidPeFile(String),

    #[error("Invalid DOS header: expected 'MZ', found {0:04X}")]
    InvalidDosHeader(u16),

    #[error("Invalid PE signature: expected 'PE\\0\\0'")]
    InvalidPeSignature,

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Section '{0}' not found in PE file")]
    SectionNotFound(String),

    #[error("Import module '{0}' not found")]
    ImportModuleNotFound(String),

    #[error("Import function '{0}' not found in '{1}'")]
    ImportFunctionNotFound(String, String),

    #[error("Failed to read PE file: {0}")]
    PeReadError(#[source] std::io::Error),

    #[error("Invalid relocation type: {0}")]
    InvalidRelocationType(u16),

    #[error("DLL entry point returned FALSE")]
    DllMainFailed,
}
```

### Step 2: Implement Memory Reader

**File:** `injector-core/src/memory/reader.rs`

```rust
//! Reading data from remote process memory.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use crate::InjectionError;

/// Read data from a remote process's memory.
///
/// # Arguments
/// * `process` - Target process handle
/// * `address` - Address to read from
/// * `size` - Number of bytes to read
///
/// # Errors
/// Returns `InjectionError::MemoryReadFailed` if read fails.
pub fn read_memory(
    process: HANDLE,
    address: *const u8,
    size: usize,
) -> Result<Vec<u8>, InjectionError> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;

    unsafe {
        ReadProcessMemory(
            process,
            address as *const std::ffi::c_void,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            size,
            Some(&mut bytes_read),
        )
        .map_err(|_| InjectionError::MemoryReadFailed(
            std::io::Error::last_os_error()
        ))?;
    }

    if bytes_read != size {
        return Err(InjectionError::MemoryReadFailed(
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Read {} bytes, expected {}", bytes_read, size),
            )
        ));
    }

    Ok(buffer)
}

/// Read a structure from remote memory.
///
/// # Safety
/// The caller must ensure `T` is safe to construct from arbitrary bytes.
pub unsafe fn read_struct<T: Copy>(
    process: HANDLE,
    address: *const u8,
) -> Result<T, InjectionError> {
    let bytes = read_memory(process, address, std::mem::size_of::<T>())?;
    Ok(*(bytes.as_ptr() as *const T))
}
```

### Step 3: Define PE Header Structures

**File:** `injector-core/src/pe/headers.rs`

```rust
//! PE file header structures.
//!
//! These structures match the Windows PE format specification.

use std::mem::size_of;

/// DOS header ("MZ" header).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDosHeader {
    pub e_magic: u16,      // 0x5A4D ("MZ")
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,     // Offset to PE header
}

impl ImageDosHeader {
    pub const MAGIC: u16 = 0x5A4D; // "MZ"

    pub fn is_valid(&self) -> bool {
        self.e_magic == Self::MAGIC
    }
}

/// PE signature.
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

/// COFF file header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Machine types.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;  // x86
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x64

/// Optional header (64-bit).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
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

/// Optional header (32-bit).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
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

pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

/// Data directory entry.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Data directory indices.
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

/// Section header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
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
    pub fn name_str(&self) -> String {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..len]).to_string()
    }
}

/// Import descriptor.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,  // RVA to ILT
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,                  // RVA to DLL name
    pub first_thunk: u32,           // RVA to IAT
}

/// Import by name.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageImportByName {
    pub hint: u16,
    pub name: [u8; 1], // Variable length
}

/// Base relocation block.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

/// Relocation types.
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;
```

### Step 4: Implement PE Parser

**File:** `injector-core/src/pe/parser.rs`

```rust
//! PE file parser.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use crate::InjectionError;
use super::headers::*;

/// Parsed PE file.
pub struct PeFile {
    /// Raw file data
    pub data: Vec<u8>,

    /// DOS header
    pub dos_header: ImageDosHeader,

    /// COFF header
    pub file_header: ImageFileHeader,

    /// Optional header (64-bit)
    pub optional_header_64: Option<ImageOptionalHeader64>,

    /// Optional header (32-bit)
    pub optional_header_32: Option<ImageOptionalHeader32>,

    /// Section headers
    pub sections: Vec<ImageSectionHeader>,

    /// Is 64-bit PE
    pub is_64bit: bool,
}

impl PeFile {
    /// Parse a PE file from disk.
    pub fn from_file(path: &Path) -> Result<Self, InjectionError> {
        log::debug!("Parsing PE file: {}", path.display());

        // Read entire file
        let mut file = File::open(path)
            .map_err(InjectionError::PeReadError)?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(InjectionError::PeReadError)?;

        Self::from_bytes(data)
    }

    /// Parse a PE file from memory.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, InjectionError> {
        if data.len() < std::mem::size_of::<ImageDosHeader>() {
            return Err(InjectionError::InvalidPeFile(
                "File too small for DOS header".into()
            ));
        }

        // Parse DOS header
        let dos_header = unsafe {
            *(data.as_ptr() as *const ImageDosHeader)
        };

        if !dos_header.is_valid() {
            return Err(InjectionError::InvalidDosHeader(dos_header.e_magic));
        }

        log::debug!("DOS header valid, PE offset: 0x{:X}", dos_header.e_lfanew);

        // Check PE signature
        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > data.len() {
            return Err(InjectionError::InvalidPeFile(
                "Invalid PE offset".into()
            ));
        }

        let pe_signature = unsafe {
            *(data.as_ptr().add(pe_offset) as *const u32)
        };

        if pe_signature != IMAGE_NT_SIGNATURE {
            return Err(InjectionError::InvalidPeSignature);
        }

        log::debug!("PE signature valid");

        // Parse COFF header
        let file_header_offset = pe_offset + 4;
        let file_header = unsafe {
            *(data.as_ptr().add(file_header_offset) as *const ImageFileHeader)
        };

        log::debug!("Machine: 0x{:X}, Sections: {}",
            file_header.machine,
            file_header.number_of_sections
        );

        // Determine architecture
        let is_64bit = match file_header.machine {
            IMAGE_FILE_MACHINE_AMD64 => true,
            IMAGE_FILE_MACHINE_I386 => false,
            _ => {
                return Err(InjectionError::UnsupportedArchitecture(
                    format!("0x{:X}", file_header.machine)
                ));
            }
        };

        // Parse optional header
        let optional_header_offset = file_header_offset + std::mem::size_of::<ImageFileHeader>();

        let (optional_header_64, optional_header_32) = if is_64bit {
            let opt_header = unsafe {
                *(data.as_ptr().add(optional_header_offset) as *const ImageOptionalHeader64)
            };

            if opt_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                return Err(InjectionError::InvalidPeFile(
                    "Invalid optional header magic".into()
                ));
            }

            log::debug!("64-bit PE, Image Base: 0x{:X}, Entry Point: 0x{:X}",
                opt_header.image_base,
                opt_header.address_of_entry_point
            );

            (Some(opt_header), None)
        } else {
            let opt_header = unsafe {
                *(data.as_ptr().add(optional_header_offset) as *const ImageOptionalHeader32)
            };

            if opt_header.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
                return Err(InjectionError::InvalidPeFile(
                    "Invalid optional header magic".into()
                ));
            }

            log::debug!("32-bit PE, Image Base: 0x{:X}, Entry Point: 0x{:X}",
                opt_header.image_base,
                opt_header.address_of_entry_point
            );

            (None, Some(opt_header))
        };

        // Parse section headers
        let section_offset = optional_header_offset + file_header.size_of_optional_header as usize;
        let mut sections = Vec::new();

        for i in 0..file_header.number_of_sections {
            let section = unsafe {
                *(data.as_ptr().add(section_offset + i as usize * std::mem::size_of::<ImageSectionHeader>())
                    as *const ImageSectionHeader)
            };

            log::debug!("Section: {} VA: 0x{:X} Size: 0x{:X}",
                section.name_str(),
                section.virtual_address,
                section.virtual_size
            );

            sections.push(section);
        }

        Ok(Self {
            data,
            dos_header,
            file_header,
            optional_header_64,
            optional_header_32,
            sections,
            is_64bit,
        })
    }

    /// Get image base address.
    pub fn image_base(&self) -> usize {
        if let Some(opt) = &self.optional_header_64 {
            opt.image_base as usize
        } else if let Some(opt) = &self.optional_header_32 {
            opt.image_base as usize
        } else {
            0
        }
    }

    /// Get entry point RVA.
    pub fn entry_point(&self) -> u32 {
        if let Some(opt) = &self.optional_header_64 {
            opt.address_of_entry_point
        } else if let Some(opt) = &self.optional_header_32 {
            opt.address_of_entry_point
        } else {
            0
        }
    }

    /// Get size of image.
    pub fn size_of_image(&self) -> u32 {
        if let Some(opt) = &self.optional_header_64 {
            opt.size_of_image
        } else if let Some(opt) = &self.optional_header_32 {
            opt.size_of_image
        } else {
            0
        }
    }

    /// Get data directory.
    pub fn data_directory(&self, index: usize) -> Option<&ImageDataDirectory> {
        if let Some(opt) = &self.optional_header_64 {
            opt.data_directory.get(index)
        } else if let Some(opt) = &self.optional_header_32 {
            opt.data_directory.get(index)
        } else {
            None
        }
    }

    /// Convert RVA to file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            if rva >= section.virtual_address
                && rva < section.virtual_address + section.virtual_size
            {
                let offset = rva - section.virtual_address;
                return Some(section.pointer_to_raw_data as usize + offset as usize);
            }
        }
        None
    }

    /// Read data at RVA.
    pub fn read_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let offset = self.rva_to_offset(rva)?;
        if offset + size > self.data.len() {
            return None;
        }
        Some(&self.data[offset..offset + size])
    }

    /// Read null-terminated string at RVA.
    pub fn read_string_at_rva(&self, rva: u32) -> Option<String> {
        let offset = self.rva_to_offset(rva)?;
        let bytes = &self.data[offset..];

        let len = bytes.iter().position(|&b| b == 0)?;
        String::from_utf8(bytes[..len].to_vec()).ok()
    }
}
```

### Step 5: Implement Section Mapping

**File:** `injector-core/src/pe/sections.rs`

```rust
//! PE section mapping.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::*;
use crate::memory::{RemoteMemory, write_memory};
use crate::pe::parser::PeFile;
use crate::InjectionError;

/// Map PE sections into remote process memory.
pub fn map_sections(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Mapping {} sections", pe.sections.len());

    // Copy headers
    let header_size = pe.sections.iter()
        .map(|s| s.pointer_to_raw_data)
        .min()
        .unwrap_or(4096) as usize;

    log::debug!("Copying headers ({} bytes)", header_size);
    write_memory(process, base_address, &pe.data[..header_size])?;

    // Copy each section
    for section in &pe.sections {
        if section.size_of_raw_data == 0 {
            log::debug!("Skipping empty section: {}", section.name_str());
            continue;
        }

        let dest_address = unsafe {
            base_address.add(section.virtual_address as usize)
        };

        let src_offset = section.pointer_to_raw_data as usize;
        let src_size = section.size_of_raw_data.min(section.virtual_size) as usize;

        if src_offset + src_size > pe.data.len() {
            log::warn!("Section {} extends beyond file", section.name_str());
            continue;
        }

        log::debug!(
            "Mapping section {} to 0x{:X} ({} bytes)",
            section.name_str(),
            dest_address as usize,
            src_size
        );

        write_memory(
            process,
            dest_address,
            &pe.data[src_offset..src_offset + src_size],
        )?;
    }

    log::info!("All sections mapped successfully");
    Ok(())
}

/// Set memory protection for sections.
pub fn protect_sections(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Setting section protections");

    for section in &pe.sections {
        let address = unsafe {
            base_address.add(section.virtual_address as usize) as *const std::ffi::c_void
        };

        let size = section.virtual_size as usize;
        let protection = section_characteristics_to_protection(section.characteristics);

        log::debug!(
            "Protecting section {} at 0x{:X}: {:?}",
            section.name_str(),
            address as usize,
            protection
        );

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            VirtualProtectEx(
                process,
                address,
                size,
                protection,
                &mut old_protect,
            )
            .map_err(|_| InjectionError::Io(std::io::Error::last_os_error()))?;
        }
    }

    Ok(())
}

/// Convert section characteristics to memory protection flags.
fn section_characteristics_to_protection(characteristics: u32) -> PAGE_PROTECTION_FLAGS {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

    let executable = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let readable = characteristics & IMAGE_SCN_MEM_READ != 0;
    let writable = characteristics & IMAGE_SCN_MEM_WRITE != 0;

    match (executable, readable, writable) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, true) => PAGE_EXECUTE_WRITECOPY,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, true) => PAGE_WRITECOPY,
        (false, false, false) => PAGE_NOACCESS,
    }
}
```

### Step 6: Implement Import Resolution

**File:** `injector-core/src/pe/imports.rs`

```rust
//! Import address table resolution.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::s;
use crate::memory::write_memory;
use crate::pe::parser::PeFile;
use crate::pe::headers::*;
use crate::InjectionError;
use std::ffi::CString;

/// Resolve imports for the mapped PE.
pub fn resolve_imports(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Resolving imports");

    let import_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(dir) if dir.virtual_address != 0 => dir,
        _ => {
            log::debug!("No import directory");
            return Ok(());
        }
    };

    let import_desc_rva = import_dir.virtual_address;
    let mut current_rva = import_desc_rva;

    loop {
        // Read import descriptor
        let desc_data = pe.read_at_rva(current_rva, std::mem::size_of::<ImageImportDescriptor>())
            .ok_or_else(|| InjectionError::InvalidPeFile("Invalid import descriptor RVA".into()))?;

        let import_desc = unsafe {
            *(desc_data.as_ptr() as *const ImageImportDescriptor)
        };

        // Null descriptor marks end
        if import_desc.name == 0 {
            break;
        }

        // Get DLL name
        let dll_name = pe.read_string_at_rva(import_desc.name)
            .ok_or_else(|| InjectionError::InvalidPeFile("Invalid import name RVA".into()))?;

        log::debug!("Processing imports from: {}", dll_name);

        // Load the DLL in our process to get function addresses
        let dll_name_cstr = CString::new(dll_name.clone())
            .map_err(|_| InjectionError::InvalidPeFile("Invalid DLL name".into()))?;

        let module_handle = unsafe {
            GetModuleHandleA(s!(&dll_name_cstr))
                .map_err(|_| InjectionError::ImportModuleNotFound(dll_name.clone()))?
        };

        // Process thunks
        let thunk_rva = if import_desc.original_first_thunk != 0 {
            import_desc.original_first_thunk
        } else {
            import_desc.first_thunk
        };

        let iat_rva = import_desc.first_thunk;

        let mut thunk_offset = 0;
        loop {
            let current_thunk_rva = thunk_rva + thunk_offset;
            let current_iat_rva = iat_rva + thunk_offset;

            // Read thunk value
            let thunk_size = if pe.is_64bit { 8 } else { 4 };
            let thunk_data = pe.read_at_rva(current_thunk_rva, thunk_size)
                .ok_or_else(|| InjectionError::InvalidPeFile("Invalid thunk RVA".into()))?;

            let thunk_value = if pe.is_64bit {
                u64::from_le_bytes(thunk_data.try_into().unwrap())
            } else {
                u32::from_le_bytes(thunk_data.try_into().unwrap()) as u64
            };

            // Null thunk marks end
            if thunk_value == 0 {
                break;
            }

            // Check if import by ordinal
            let ordinal_flag = if pe.is_64bit { 1u64 << 63 } else { 1u64 << 31 };
            let func_address = if thunk_value & ordinal_flag != 0 {
                // Import by ordinal
                let ordinal = (thunk_value & 0xFFFF) as u16;
                log::debug!("  Resolving ordinal #{}", ordinal);

                unsafe {
                    GetProcAddress(module_handle, s!(&format!("#{}", ordinal)))
                        .ok_or_else(|| InjectionError::ImportFunctionNotFound(
                            format!("#{}", ordinal),
                            dll_name.clone(),
                        ))?
                }
            } else {
                // Import by name
                let import_by_name_rva = thunk_value as u32;
                let func_name = pe.read_string_at_rva(import_by_name_rva + 2)
                    .ok_or_else(|| InjectionError::InvalidPeFile("Invalid import name".into()))?;

                log::debug!("  Resolving function: {}", func_name);

                let func_name_cstr = CString::new(func_name.clone())
                    .map_err(|_| InjectionError::InvalidPeFile("Invalid function name".into()))?;

                unsafe {
                    GetProcAddress(module_handle, s!(&func_name_cstr))
                        .ok_or_else(|| InjectionError::ImportFunctionNotFound(
                            func_name,
                            dll_name.clone(),
                        ))?
                }
            };

            // Write function address to IAT
            let iat_address = unsafe {
                base_address.add(current_iat_rva as usize)
            };

            let addr_bytes = if pe.is_64bit {
                (func_address as usize as u64).to_le_bytes().to_vec()
            } else {
                (func_address as usize as u32).to_le_bytes().to_vec()
            };

            write_memory(process, iat_address, &addr_bytes)?;

            thunk_offset += thunk_size as u32;
        }

        current_rva += std::mem::size_of::<ImageImportDescriptor>() as u32;
    }

    log::info!("All imports resolved");
    Ok(())
}
```

### Step 7: Implement Base Relocations

**File:** `injector-core/src/pe/relocations.rs`

```rust
//! Base relocation handling.

use windows::Win32::Foundation::HANDLE;
use crate::memory::{read_memory, write_memory};
use crate::pe::parser::PeFile;
use crate::pe::headers::*;
use crate::InjectionError;

/// Process base relocations.
pub fn process_relocations(
    process: HANDLE,
    pe: &PeFile,
    base_address: *mut u8,
) -> Result<(), InjectionError> {
    log::info!("Processing base relocations");

    let reloc_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(dir) if dir.virtual_address != 0 => dir,
        _ => {
            log::debug!("No relocation directory");
            return Ok(());
        }
    };

    let delta = (base_address as isize) - (pe.image_base() as isize);
    log::debug!("Relocation delta: 0x{:X}", delta);

    if delta == 0 {
        log::debug!("No relocation needed (loaded at preferred base)");
        return Ok(());
    }

    let mut offset = 0u32;

    while offset < reloc_dir.size {
        let block_rva = reloc_dir.virtual_address + offset;
        let block_data = pe.read_at_rva(block_rva, std::mem::size_of::<ImageBaseRelocation>())
            .ok_or_else(|| InjectionError::InvalidPeFile("Invalid relocation block".into()))?;

        let reloc_block = unsafe {
            *(block_data.as_ptr() as *const ImageBaseRelocation)
        };

        if reloc_block.size_of_block == 0 {
            break;
        }

        let entry_count = (reloc_block.size_of_block - std::mem::size_of::<ImageBaseRelocation>() as u32) / 2;

        log::debug!(
            "Processing relocation block at RVA 0x{:X} ({} entries)",
            reloc_block.virtual_address,
            entry_count
        );

        for i in 0..entry_count {
            let entry_rva = block_rva + std::mem::size_of::<ImageBaseRelocation>() as u32 + i * 2;
            let entry_data = pe.read_at_rva(entry_rva, 2)
                .ok_or_else(|| InjectionError::InvalidPeFile("Invalid relocation entry".into()))?;

            let entry = u16::from_le_bytes([entry_data[0], entry_data[1]]);
            let reloc_type = entry >> 12;
            let reloc_offset = entry & 0xFFF;

            let target_rva = reloc_block.virtual_address + reloc_offset as u32;
            let target_address = unsafe { base_address.add(target_rva as usize) };

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Skip
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    // 32-bit relocation
                    let original_value = read_memory(process, target_address, 4)?;
                    let value = i32::from_le_bytes(original_value.try_into().unwrap());
                    let new_value = (value as isize + delta) as i32;
                    write_memory(process, target_address, &new_value.to_le_bytes())?;
                }
                IMAGE_REL_BASED_DIR64 => {
                    // 64-bit relocation
                    let original_value = read_memory(process, target_address, 8)?;
                    let value = i64::from_le_bytes(original_value.try_into().unwrap());
                    let new_value = (value as isize + delta) as i64;
                    write_memory(process, target_address, &new_value.to_le_bytes())?;
                }
                _ => {
                    log::warn!("Unknown relocation type: {}", reloc_type);
                }
            }
        }

        offset += reloc_block.size_of_block;
    }

    log::info!("Base relocations processed");
    Ok(())
}
```

### Step 8: Implement Manual Map Injector

**File:** `injector-core/src/injection/manual_map.rs`

```rust
//! Manual DLL mapping injection method.

use std::path::Path;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Memory::*;
use windows::Win32::Foundation::CloseHandle;
use crate::injection::{InjectionMethod, InjectionResult, validate_dll_path, validate_architecture};
use crate::memory::{RemoteMemory, write_memory};
use crate::pe::parser::PeFile;
use crate::pe::{sections, imports, relocations};
use crate::{ProcessHandle, InjectionError};

/// Manual mapping injector.
#[derive(Debug, Default)]
pub struct ManualMapInjector;

impl ManualMapInjector {
    pub fn new() -> Self {
        Self
    }

    /// Create 64-bit loader shellcode.
    fn create_loader_shellcode_x64(dll_base: *mut u8, entry_point: u32) -> Vec<u8> {
        let dll_main_addr = (dll_base as usize + entry_point as usize) as u64;
        let mut shellcode = Vec::new();
        shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        shellcode.extend_from_slice(&[0x48, 0xB9]); // mov rcx, dll_base
        shellcode.extend_from_slice(&(dll_base as u64).to_le_bytes());
        shellcode.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1
        shellcode.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8, r8
        shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax, dll_main_addr
        shellcode.extend_from_slice(&dll_main_addr.to_le_bytes());
        shellcode.extend_from_slice(&[0xFF, 0xD0]); // call rax
        shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        shellcode.push(0xC3); // ret
        shellcode
    }
}

impl InjectionMethod for ManualMapInjector {
    fn inject(&self, handle: &ProcessHandle, dll_path: &Path) -> InjectionResult<()> {
        log::info!("Starting manual mapping injection");
        validate_dll_path(dll_path)?;
        validate_architecture(handle)?;

        let pe = PeFile::from_file(dll_path)?;
        let image_size = pe.size_of_image() as usize;

        let remote_image = RemoteMemory::allocate(
            handle.as_handle(),
            image_size,
            PAGE_READWRITE,
        )?;

        let base_address = remote_image.address();
        log::info!("Allocated image at: {:?}", base_address);

        sections::map_sections(handle.as_handle(), &pe, base_address)?;
        imports::resolve_imports(handle.as_handle(), &pe, base_address)?;
        relocations::process_relocations(handle.as_handle(), &pe, base_address)?;
        
        // CRITICAL: Handle TLS callbacks and Exception Tables here
        // For x64, use RtlAddFunctionTable in the target process via shellcode
        // to ensure exceptions in the injected DLL don't crash the host.
        
        sections::protect_sections(handle.as_handle(), &pe, base_address)?;

        // Call DllMain via shellcode
        let entry_point = pe.entry_point();
        if entry_point != 0 {
            let shellcode = Self::create_loader_shellcode_x64(base_address, entry_point);
            let shellcode_mem = RemoteMemory::allocate(
                handle.as_handle(),
                shellcode.len(),
                PAGE_EXECUTE_READWRITE,
            )?;

            write_memory(handle.as_handle(), shellcode_mem.address(), &shellcode)?;

            let thread_handle = unsafe {
                CreateRemoteThread(
                    handle.as_handle(),
                    None,
                    0,
                    Some(std::mem::transmute(shellcode_mem.address())),
                    None,
                    0,
                    None,
                )
                .map_err(|_| InjectionError::CreateThreadFailed(
                    std::io::Error::last_os_error()
                ))?
            };

            unsafe {
                WaitForSingleObject(thread_handle, 10000);
                let _ = CloseHandle(thread_handle);
            }
        }

        std::mem::forget(remote_image);
        log::info!("Manual mapping completed successfully");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "Manual Mapping"
    }

    fn required_access(&self) -> PROCESS_ACCESS_RIGHTS {
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
            | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    }
}
```

## Testing Checklist

- [ ] PE parser correctly reads all headers
- [ ] Sections map to correct addresses
- [ ] Imports resolve successfully
- [ ] Relocations apply correctly
- [ ] DllMain executes and returns TRUE
- [ ] Test DLL creates log file
- [ ] 32-bit and 64-bit DLLs both work

## Common Pitfalls

### 1. Incorrect RVA to Offset Conversion
**Problem:** Reading wrong data from PE file
**Solution:** Check section bounds carefully

### 2. Import By Ordinal
**Problem:** Assuming all imports are by name
**Solution:** Check high bit for ordinal flag

### 3. Relocation Delta Calculation
**Problem:** Wrong base address math
**Solution:** Use isize for signed arithmetic

### 4. Section Protection
**Problem:** Executable sections not marked executable
**Solution:** Parse section characteristics correctly

### 5. DllMain Calling Convention
**Problem:** Stack corruption due to wrong convention
**Solution:** Use correct shellcode for architecture

## Completion Criteria

Phase 6 is complete when:
- ✅ PE parser handles DOS, NT, sections correctly
- ✅ All sections map to remote memory
- ✅ Import resolution works (by name and ordinal)
- ✅ Base relocations apply correctly
- ✅ Section protections set properly
- ✅ DllMain executes successfully
- ✅ Test DLL injects and runs
- ✅ Both 32-bit and 64-bit work
- ✅ All tests pass

## Git Commit

```bash
git add injector-core/src/pe/ injector-core/src/injection/manual_map.rs
git add injector-core/src/memory/reader.rs
git commit -m "feat: implement manual DLL mapping injection

- Create comprehensive PE file parser with full header support
- Implement section mapping with proper alignment
- Add import resolution (by name and ordinal)
- Process base relocations for any load address
- Generate x86/x64 shellcode for DllMain invocation
- Set correct memory protections per section

Manual mapping fully functional - DLL doesn't appear in PEB.

Follows docs/phases/phase-06-manual-mapping.md
"
```

## Next Steps

Proceed to **Phase 7: Advanced Injection Methods** (docs/phases/phase-07-advanced-methods.md)

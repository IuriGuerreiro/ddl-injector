//! PE file format parser.

use std::path::Path;
use std::fs;
use std::mem;
use crate::InjectionError;
use super::headers::*;

/// Represents a parsed PE file with all its headers and sections.
pub struct PeFile {
    /// Raw file data
    pub data: Vec<u8>,
    /// DOS header
    pub dos_header: ImageDosHeader,
    /// COFF file header
    pub file_header: ImageFileHeader,
    /// Optional header (64-bit)
    pub optional_header_64: Option<ImageOptionalHeader64>,
    /// Optional header (32-bit)
    pub optional_header_32: Option<ImageOptionalHeader32>,
    /// Section headers
    pub sections: Vec<ImageSectionHeader>,
    /// Whether this is a 64-bit PE file
    pub is_64bit: bool,
}

impl PeFile {
    /// Load and parse a PE file from disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, InjectionError> {
        log::debug!("Loading PE file from: {}", path.as_ref().display());

        let data = fs::read(path.as_ref())
            .map_err(InjectionError::PeReadError)?;

        Self::from_bytes(data)
    }

    /// Parse a PE file from memory.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, InjectionError> {
        log::debug!("Parsing PE file ({} bytes)", data.len());

        // Parse DOS header
        if data.len() < mem::size_of::<ImageDosHeader>() {
            return Err(InjectionError::InvalidPeFile(
                "File too small for DOS header".to_string(),
            ));
        }

        let dos_header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ImageDosHeader) };

        log::debug!(
            "DOS header: magic=0x{:04X}, e_lfanew=0x{:08X}",
            dos_header.e_magic,
            dos_header.e_lfanew
        );

        dos_header.validate()?;

        // Validate e_lfanew offset
        if dos_header.e_lfanew < 0 || (dos_header.e_lfanew as usize) >= data.len() {
            return Err(InjectionError::InvalidPeFile(format!(
                "Invalid e_lfanew offset: 0x{:08X}",
                dos_header.e_lfanew
            )));
        }

        let nt_offset = dos_header.e_lfanew as usize;

        // Parse NT signature
        if nt_offset + 4 > data.len() {
            return Err(InjectionError::InvalidPeFile(
                "File too small for NT headers".to_string(),
            ));
        }

        let nt_signature = u32::from_le_bytes([
            data[nt_offset],
            data[nt_offset + 1],
            data[nt_offset + 2],
            data[nt_offset + 3],
        ]);

        log::debug!("NT signature: 0x{:08X}", nt_signature);

        if nt_signature != IMAGE_NT_SIGNATURE {
            return Err(InjectionError::InvalidPeSignature);
        }

        // Parse COFF file header
        let file_header_offset = nt_offset + 4;
        if file_header_offset + mem::size_of::<ImageFileHeader>() > data.len() {
            return Err(InjectionError::InvalidPeFile(
                "File too small for COFF header".to_string(),
            ));
        }

        let file_header = unsafe {
            std::ptr::read_unaligned(data.as_ptr().add(file_header_offset) as *const ImageFileHeader)
        };

        log::debug!(
            "File header: machine=0x{:04X}, sections={}, optional_header_size={}",
            file_header.machine,
            file_header.number_of_sections,
            file_header.size_of_optional_header
        );

        // Determine architecture
        let is_64bit = match file_header.machine {
            IMAGE_FILE_MACHINE_I386 => {
                log::debug!("Architecture: x86 (32-bit)");
                false
            }
            IMAGE_FILE_MACHINE_AMD64 => {
                log::debug!("Architecture: x64 (64-bit)");
                true
            }
            _ => {
                return Err(InjectionError::UnsupportedArchitecture(format!(
                    "Machine type: 0x{:04X}",
                    file_header.machine
                )));
            }
        };

        // Parse optional header
        let optional_header_offset = file_header_offset + mem::size_of::<ImageFileHeader>();

        let (optional_header_64, optional_header_32) = if is_64bit {
            if optional_header_offset + mem::size_of::<ImageOptionalHeader64>() > data.len() {
                return Err(InjectionError::InvalidPeFile(
                    "File too small for optional header (64-bit)".to_string(),
                ));
            }
            let opt_header = unsafe {
                std::ptr::read_unaligned(
                    data.as_ptr().add(optional_header_offset) as *const ImageOptionalHeader64
                )
            };
            log::debug!("Optional header (64-bit): magic=0x{:04X}, entry_point=0x{:08X}, image_base=0x{:016X}",
                opt_header.magic, opt_header.address_of_entry_point, opt_header.image_base);
            (Some(opt_header), None)
        } else {
            if optional_header_offset + mem::size_of::<ImageOptionalHeader32>() > data.len() {
                return Err(InjectionError::InvalidPeFile(
                    "File too small for optional header (32-bit)".to_string(),
                ));
            }
            let opt_header = unsafe {
                std::ptr::read_unaligned(
                    data.as_ptr().add(optional_header_offset) as *const ImageOptionalHeader32
                )
            };
            log::debug!("Optional header (32-bit): magic=0x{:04X}, entry_point=0x{:08X}, image_base=0x{:08X}",
                opt_header.magic, opt_header.address_of_entry_point, opt_header.image_base);
            (None, Some(opt_header))
        };

        // Parse section headers
        let section_table_offset =
            optional_header_offset + file_header.size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(file_header.number_of_sections as usize);

        log::debug!(
            "Parsing {} sections at offset 0x{:08X}",
            file_header.number_of_sections,
            section_table_offset
        );

        for i in 0..file_header.number_of_sections {
            let section_offset =
                section_table_offset + (i as usize * mem::size_of::<ImageSectionHeader>());

            if section_offset + mem::size_of::<ImageSectionHeader>() > data.len() {
                return Err(InjectionError::InvalidPeFile(format!(
                    "File too small for section header {}",
                    i
                )));
            }

            let section = unsafe {
                std::ptr::read_unaligned(
                    data.as_ptr().add(section_offset) as *const ImageSectionHeader
                )
            };

            log::debug!("  Section {}: {:?}", i, section);
            sections.push(section);
        }

        Ok(PeFile {
            data,
            dos_header,
            file_header,
            optional_header_64,
            optional_header_32,
            sections,
            is_64bit,
        })
    }

    /// Get the preferred image base address.
    pub fn image_base(&self) -> u64 {
        if let Some(ref opt) = self.optional_header_64 {
            opt.image_base
        } else if let Some(ref opt) = self.optional_header_32 {
            opt.image_base as u64
        } else {
            0
        }
    }

    /// Get the entry point RVA.
    pub fn entry_point(&self) -> u32 {
        if let Some(ref opt) = self.optional_header_64 {
            opt.address_of_entry_point
        } else if let Some(ref opt) = self.optional_header_32 {
            opt.address_of_entry_point
        } else {
            0
        }
    }

    /// Get the total size of the image in memory.
    pub fn size_of_image(&self) -> u32 {
        if let Some(ref opt) = self.optional_header_64 {
            opt.size_of_image
        } else if let Some(ref opt) = self.optional_header_32 {
            opt.size_of_image
        } else {
            0
        }
    }

    /// Get the size of headers.
    pub fn size_of_headers(&self) -> u32 {
        if let Some(ref opt) = self.optional_header_64 {
            opt.size_of_headers
        } else if let Some(ref opt) = self.optional_header_32 {
            opt.size_of_headers
        } else {
            0
        }
    }

    /// Get a data directory by index.
    pub fn data_directory(&self, index: usize) -> Option<ImageDataDirectory> {
        if let Some(ref opt) = self.optional_header_64 {
            if index < opt.data_directory.len() {
                return Some(opt.data_directory[index]);
            }
        } else if let Some(ref opt) = self.optional_header_32 {
            if index < opt.data_directory.len() {
                return Some(opt.data_directory[index]);
            }
        }
        None
    }

    /// Convert an RVA (Relative Virtual Address) to a file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        // Check if RVA is in headers
        if rva < self.size_of_headers() {
            return Some(rva as usize);
        }

        // Search sections
        for section in &self.sections {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some(section.pointer_to_raw_data as usize + offset_in_section as usize);
            }
        }

        None
    }

    /// Read data at an RVA.
    pub fn read_at_rva(&self, rva: u32, size: usize) -> Result<&[u8], InjectionError> {
        let offset = self.rva_to_offset(rva)
            .ok_or_else(|| InjectionError::InvalidPeFile(
                format!("Invalid RVA: 0x{:08X}", rva)
            ))?;

        if offset + size > self.data.len() {
            return Err(InjectionError::InvalidPeFile(
                format!("Read beyond file bounds at RVA 0x{:08X}", rva)
            ));
        }

        Ok(&self.data[offset..offset + size])
    }

    /// Read a null-terminated string at an RVA.
    pub fn read_string_at_rva(&self, rva: u32) -> Result<String, InjectionError> {
        let offset = self.rva_to_offset(rva)
            .ok_or_else(|| InjectionError::InvalidPeFile(
                format!("Invalid RVA for string: 0x{:08X}", rva)
            ))?;

        let bytes = &self.data[offset..];
        let len = bytes.iter().position(|&c| c == 0)
            .ok_or_else(|| InjectionError::InvalidPeFile(
                format!("Unterminated string at RVA 0x{:08X}", rva)
            ))?;

        Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
    }
}

//! Native Windows API helpers.
//!
//! This module provides access to undocumented or low-level NT APIs
//! from ntdll.dll that are not available in standard Windows crates.

use crate::error::InjectionError;
use windows::core::s;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

/// Status code returned by NT API functions.
pub type NTSTATUS = i32;

/// NT_SUCCESS macro equivalent
#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Section access rights
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const SECTION_ALL_ACCESS: u32 = 0x000F001F;

/// Section allocation attributes
pub const SEC_COMMIT: u32 = 0x08000000;
pub const SEC_IMAGE: u32 = 0x01000000;
pub const SEC_RESERVE: u32 = 0x04000000;

/// View mapping flags
pub const VIEW_SHARE: u32 = 0x01;
pub const VIEW_UNMAP: u32 = 0x02;

/// Allocation type for sections
#[repr(C)]
pub enum SectionInherit {
    ViewShare = 1,
    ViewUnmap = 2,
}

/// NtCreateSection function pointer type
type NtCreateSectionFn = unsafe extern "system" fn(
    section_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const std::ffi::c_void,
    maximum_size: *const i64,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS;

/// NtMapViewOfSection function pointer type
type NtMapViewOfSectionFn = unsafe extern "system" fn(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut *mut std::ffi::c_void,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *const i64,
    view_size: *mut usize,
    inherit_disposition: SectionInherit,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS;

/// NtUnmapViewOfSection function pointer type
type NtUnmapViewOfSectionFn =
    unsafe extern "system" fn(process_handle: HANDLE, base_address: *mut std::ffi::c_void) -> NTSTATUS;

/// Get the address of NtCreateSection from ntdll.dll
pub fn get_nt_create_section() -> Result<NtCreateSectionFn, InjectionError> {
    unsafe {
        let ntdll = GetModuleHandleA(s!("ntdll.dll"))
            .map_err(|_| InjectionError::NtCreateSectionNotFound)?;

        let func_addr = GetProcAddress(ntdll, s!("NtCreateSection"))
            .ok_or(InjectionError::NtCreateSectionNotFound)?;

        Ok(std::mem::transmute::<*const usize, NtCreateSectionFn>(
            func_addr as *const usize,
        ))
    }
}

/// Get the address of NtMapViewOfSection from ntdll.dll
pub fn get_nt_map_view_of_section() -> Result<NtMapViewOfSectionFn, InjectionError> {
    unsafe {
        let ntdll = GetModuleHandleA(s!("ntdll.dll"))
            .map_err(|_| InjectionError::NtMapViewOfSectionNotFound)?;

        let func_addr = GetProcAddress(ntdll, s!("NtMapViewOfSection"))
            .ok_or(InjectionError::NtMapViewOfSectionNotFound)?;

        Ok(std::mem::transmute::<*const usize, NtMapViewOfSectionFn>(
            func_addr as *const usize,
        ))
    }
}

/// Get the address of NtUnmapViewOfSection from ntdll.dll
pub fn get_nt_unmap_view_of_section() -> Result<NtUnmapViewOfSectionFn, InjectionError> {
    unsafe {
        let ntdll = GetModuleHandleA(s!("ntdll.dll"))
            .map_err(|_| InjectionError::NtUnmapViewOfSectionNotFound)?;

        let func_addr = GetProcAddress(ntdll, s!("NtUnmapViewOfSection"))
            .ok_or(InjectionError::NtUnmapViewOfSectionNotFound)?;

        Ok(std::mem::transmute::<*const usize, NtUnmapViewOfSectionFn>(
            func_addr as *const usize,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_nt_create_section() {
        let result = get_nt_create_section();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_nt_map_view_of_section() {
        let result = get_nt_map_view_of_section();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_nt_unmap_view_of_section() {
        let result = get_nt_unmap_view_of_section();
        assert!(result.is_ok());
    }

    #[test]
    fn test_nt_success() {
        assert!(nt_success(0));
        assert!(nt_success(1));
        assert!(!nt_success(-1));
        assert!(!nt_success(-2147483648)); // 0x80000000
    }
}

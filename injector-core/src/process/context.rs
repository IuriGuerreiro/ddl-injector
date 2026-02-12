//! Thread context management.
//!
//! This module provides safe wrappers around Windows thread context operations,
//! used primarily for thread hijacking injection.

use crate::error::ProcessError;
use crate::process::ThreadHandle;
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_FLAGS, GetThreadContext, SetThreadContext};

/// RAII wrapper for thread context.
///
/// Provides safe access to thread context (CPU registers) for a suspended thread.
pub struct ThreadContext {
    context: CONTEXT,
    is_64bit: bool,
}

impl ThreadContext {
    /// Capture the context of a suspended thread.
    ///
    /// # Safety
    /// The thread must be suspended before calling this function.
    pub fn capture(thread: &ThreadHandle) -> Result<Self, ProcessError> {
        let is_64bit = cfg!(target_pointer_width = "64");

        let mut context = CONTEXT::default();

        #[cfg(target_arch = "x86_64")]
        {
            // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
            context.ContextFlags = CONTEXT_FLAGS(0x100000 | 0x1 | 0x2 | 0x4);
        }

        #[cfg(target_arch = "x86")]
        {
            // CONTEXT_i386 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
            context.ContextFlags = CONTEXT_FLAGS(0x10000 | 0x1 | 0x2 | 0x4);
        }

        unsafe {
            GetThreadContext(thread.as_handle(), &mut context)
                .map_err(|_| ProcessError::ThreadContextFailed(std::io::Error::last_os_error()))?;
        }

        Ok(Self { context, is_64bit })
    }

    /// Get the instruction pointer from the context.
    #[cfg(target_arch = "x86_64")]
    pub fn get_instruction_pointer(&self) -> usize {
        self.context.Rip as usize
    }

    #[cfg(target_arch = "x86")]
    pub fn get_instruction_pointer(&self) -> usize {
        self.context.Eip as usize
    }

    /// Set the instruction pointer in the context.
    #[cfg(target_arch = "x86_64")]
    pub fn set_instruction_pointer(&mut self, address: usize) {
        self.context.Rip = address as u64;
    }

    #[cfg(target_arch = "x86")]
    pub fn set_instruction_pointer(&mut self, address: usize) {
        self.context.Eip = address as u32;
    }

    /// Get the stack pointer from the context.
    #[cfg(target_arch = "x86_64")]
    pub fn get_stack_pointer(&self) -> usize {
        self.context.Rsp as usize
    }

    #[cfg(target_arch = "x86")]
    pub fn get_stack_pointer(&self) -> usize {
        self.context.Esp as usize
    }

    /// Set the stack pointer in the context.
    #[cfg(target_arch = "x86_64")]
    pub fn set_stack_pointer(&mut self, address: usize) {
        self.context.Rsp = address as u64;
    }

    #[cfg(target_arch = "x86")]
    pub fn set_stack_pointer(&mut self, address: usize) {
        self.context.Esp = address as u32;
    }

    /// Apply the modified context back to the thread.
    ///
    /// # Safety
    /// The thread must be suspended before calling this function.
    pub fn apply(&self, thread: &ThreadHandle) -> Result<(), ProcessError> {
        unsafe {
            SetThreadContext(thread.as_handle(), &self.context)
                .map_err(|_| ProcessError::ThreadSetContextFailed(std::io::Error::last_os_error()))?;
        }

        Ok(())
    }

    /// Get a reference to the raw context structure.
    pub fn raw(&self) -> &CONTEXT {
        &self.context
    }

    /// Get a mutable reference to the raw context structure.
    pub fn raw_mut(&mut self) -> &mut CONTEXT {
        &mut self.context
    }

    /// Check if this is a 64-bit context.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_context_own_thread() {
        // We can't test on our own thread easily, but we can test the structure
        let context = CONTEXT::default();
        assert_eq!(context.ContextFlags, CONTEXT_FLAGS(0));
    }

    #[test]
    fn test_is_64bit() {
        #[cfg(target_pointer_width = "64")]
        {
            let context = ThreadContext {
                context: CONTEXT::default(),
                is_64bit: true,
            };
            assert!(context.is_64bit());
        }

        #[cfg(target_pointer_width = "32")]
        {
            let context = ThreadContext {
                context: CONTEXT::default(),
                is_64bit: false,
            };
            assert!(!context.is_64bit());
        }
    }

    #[test]
    fn test_instruction_pointer_get_set() {
        let mut context = ThreadContext {
            context: CONTEXT::default(),
            is_64bit: cfg!(target_pointer_width = "64"),
        };

        let test_addr = 0x12345678;
        context.set_instruction_pointer(test_addr);

        #[cfg(target_arch = "x86_64")]
        assert_eq!(context.context.Rip as usize, test_addr);

        #[cfg(target_arch = "x86")]
        assert_eq!(context.context.Eip as usize, test_addr);

        assert_eq!(context.get_instruction_pointer(), test_addr);
    }

    #[test]
    fn test_stack_pointer_get_set() {
        let mut context = ThreadContext {
            context: CONTEXT::default(),
            is_64bit: cfg!(target_pointer_width = "64"),
        };

        let test_addr = 0x7FFE0000;
        context.set_stack_pointer(test_addr);

        #[cfg(target_arch = "x86_64")]
        assert_eq!(context.context.Rsp as usize, test_addr);

        #[cfg(target_arch = "x86")]
        assert_eq!(context.context.Esp as usize, test_addr);

        assert_eq!(context.get_stack_pointer(), test_addr);
    }
}

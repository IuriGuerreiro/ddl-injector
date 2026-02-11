//! Remote memory management operations.

pub mod allocator;
pub mod reader;
pub mod writer;

pub use allocator::RemoteMemory;
pub use writer::{write_memory, write_wide_string};

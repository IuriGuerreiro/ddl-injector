//! Remote memory management operations.

pub mod allocator;
pub mod reader;
pub mod writer;

pub use allocator::RemoteMemory;
pub use reader::{read_memory, read_memory_vec, read_struct};
pub use writer::{write_memory, write_wide_string};

//! PE file parsing and manipulation.

mod headers;
mod parser;
mod sections;
mod imports;
mod relocations;

pub use headers::*;
pub use parser::PeFile;
pub use sections::{map_sections, protect_sections};

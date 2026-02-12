//! PE file parsing and manipulation.

mod headers;
mod parser;
mod sections;
mod imports;
mod relocations;
mod tls;
mod exceptions;

pub use headers::*;
pub use parser::PeFile;
pub use sections::{map_sections, protect_sections};
pub use imports::resolve_imports;
pub use relocations::process_relocations;
pub use tls::process_tls_callbacks;
pub use exceptions::register_exception_handlers;

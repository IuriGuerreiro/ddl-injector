//! PE file parsing and manipulation.

mod exceptions;
mod headers;
mod imports;
mod parser;
mod relocations;
mod sections;
mod tls;

pub use exceptions::register_exception_handlers;
pub use headers::*;
pub use imports::resolve_imports;
pub use parser::PeFile;
pub use relocations::process_relocations;
pub use sections::{map_sections, protect_sections};
pub use tls::process_tls_callbacks;

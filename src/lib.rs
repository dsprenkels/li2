#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_debug_implementations,
    rust_2018_idioms,
    trivial_numeric_casts,
    unused_qualifications
)]
#![no_std]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    InternalError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InternalError => write!(f, "internal error"),
        }
    }
}

mod dilithium3;
mod params;
mod variants;

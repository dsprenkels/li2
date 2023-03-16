#![allow(
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::mut_range_bound
)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_debug_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]
#![no_std]

pub type Error = signature::Error;

// TODO: Reorganize all of the modules
mod challenge;
mod fast;
mod small;
mod expanda;
mod expandmask;
mod expands;
mod keccak;
mod ntt;
mod packing;
mod params;
mod poly;
mod reduce;
mod rounding;

#[cfg(feature = "fast")]
pub use fast::*;
#[cfg(feature = "small")]
pub use small::*;

pub use params::*;
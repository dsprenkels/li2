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
#[cfg_attr(not(feature = "std"), no_std)]

pub type Error = signature::Error;

// TODO: Reorganize all of the modules
mod challenge;
mod expanda;
mod expandmask;
mod expands;
#[cfg(feature = "fast")]
mod fast;
mod keccak;
mod ntt;
mod packing;
mod params;
mod poly;
mod reduce;
#[cfg(feature = "ring")]
mod ring;
mod rounding;
#[cfg(feature = "small")]
mod small;

#[cfg(feature = "fast")]
pub use fast::*;
#[cfg(feature = "small")]
pub use small::*;

pub use params::*;

#[cfg(feature = "ring")]
pub use ring::*;
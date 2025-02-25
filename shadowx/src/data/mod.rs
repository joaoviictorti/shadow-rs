#![allow(non_camel_case_types, non_snake_case)]

mod structs;
pub use structs::*;

mod types;
pub use types::*;

mod externs;
pub use externs::*;

mod enums;
pub use enums::*;

pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
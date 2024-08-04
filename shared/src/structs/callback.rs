extern crate alloc;
use crate::vars::Callbacks;

// Callback Information for Enumeration (Output)
#[repr(C)]
#[derive(Debug)]
pub struct CallbackInfoOutput {
    pub address: usize,
    pub name: [u16; 256],
    pub index: u8,
    pub pre_operation: usize,
    pub post_operation: usize
}

// Callback Information for Action (Input)
#[repr(C)]
#[derive(Debug)]
pub struct CallbackInfoInput {
    pub index: usize,
    pub callback: Callbacks
}

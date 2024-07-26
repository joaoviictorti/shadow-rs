use crate::vars::Callbacks;

// Callback Information for Enumeration (Output)
#[repr(C)]
#[derive(Debug)]
pub struct CallbackInfoOutput {
    pub address: usize,
    pub name: [u16; 256],
    pub index: u8,
}

// Callback Information for Action (Input)
#[repr(C)]
#[derive(Debug)]
pub struct CallbackInfoInput {
    pub index: usize,
    pub callback: Callbacks
}

// 
#[repr(C)]
#[derive(Debug)]
pub struct CallbackRestaure {
    pub index: usize,
    pub callback: Callbacks,
    pub address: u64,
}
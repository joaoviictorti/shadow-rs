extern crate alloc;

// Stores the target registry
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetRegistry {
    pub key: alloc::string::String,
    pub value: alloc::string::String,
    pub enable: bool
}
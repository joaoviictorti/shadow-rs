/// Represents information about a module in the system.
///
/// This struct is used for enumerating modules loaded in the system. It includes
/// the module's memory address, its name, and an index that can be used for
/// identification or sorting purposes.
#[repr(C)]
#[derive(Debug)]
pub struct ModuleInfo {
    /// The memory address where the module is loaded.
    pub address: usize,

    /// The name of the module, stored as a UTF-16 encoded string with a fixed length of 256.
    /// This allows compatibility with systems like Windows that use UTF-16 encoding.
    pub name: [u16; 256],

    /// The index of the module in the enumeration, useful for tracking or identifying the module.
    pub index: u8,
}

/// Represents the target module within a specific process for operations like enumeration or manipulation.
///
/// This struct contains information about the target process and the specific module within that process.
/// It includes the process identifier (PID) and the name of the module being targeted.
#[repr(C)]
#[derive(Debug)]
pub struct TargetModule {
    /// The process identifier (PID) of the process in which the target module is loaded.
    pub pid: usize,

    /// The name of the target module, stored as a dynamically allocated string.
    pub module_name: alloc::string::String,
}

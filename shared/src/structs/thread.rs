use super::LIST_ENTRY;
use core::sync::atomic::AtomicPtr;

/// Stores information about a thread that has been hidden from the system.
///
/// This struct holds the thread identifier (TID) and a pointer to the thread's
/// `LIST_ENTRY`, which is part of the system's internal list management structure.
/// The `AtomicPtr` ensures safe concurrent access to the `LIST_ENTRY`.
#[repr(C)]
#[derive(Debug)]
pub struct HiddenThreadInfo {
    /// The thread identifier (TID) of the hidden thread.
    pub tid: usize,
    
    /// A pointer to the `LIST_ENTRY` structure, which represents the thread in the system's 
    /// linked list of threads. This is wrapped in an `AtomicPtr` for safe concurrent access.
    pub list_entry: AtomicPtr<LIST_ENTRY>,
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
}

/// Stores basic information about a thread.
///
/// This struct is used to store the TID of a thread, typically for enumeration or tracking.
#[repr(C)]
#[derive(Debug)]
pub struct ThreadListInfo {
    /// The thread identifier (TID) of the thread.
    pub tids: usize,
}

/// Stores information about whether a thread is protected.
///
/// This struct holds the thread identifier (TID) and a flag indicating whether the thread
/// is protected or not. It can be used to manage or toggle protection mechanisms for a thread.
#[repr(C)]
#[derive(Debug)]
pub struct ThreadProtection {
    /// The thread identifier (TID) of the thread to be protected.
    pub tid: usize,

    /// A boolean flag indicating whether the thread is protected (`true`) or unprotected (`false`).
    pub enable: bool,
}

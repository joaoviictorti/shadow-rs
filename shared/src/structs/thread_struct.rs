use core::sync::atomic::AtomicPtr;
use super::LIST_ENTRY;

// Structure that stores the values of the process that has been hidden
#[repr(C)]
#[derive(Debug)]
pub struct HiddenThreadInfo  {
    pub tid: usize,
    pub list_entry: AtomicPtr<LIST_ENTRY>
}

// Stores the target thread
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetThread {
    pub tid: usize,
    pub enable: bool,
}

// Stores thread information
#[repr(C)]
#[derive(Debug)]
pub struct ThreadListInfo {
    pub tids: usize,
}

// Stores the thread to be protected
#[repr(C)]
#[derive(Debug)]
pub struct ThreadProtection {
    pub tid: usize,
    pub enable: bool
}

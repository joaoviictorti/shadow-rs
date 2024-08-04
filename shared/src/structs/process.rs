use core::sync::atomic::AtomicPtr;
use super::LIST_ENTRY;

// Stores the information of the process that has been hidden
#[repr(C)]
#[derive(Debug)]
pub struct HiddenProcessInfo  {
    pub pid: usize,
    pub list_entry: AtomicPtr<LIST_ENTRY>
}

// Stores process information
#[repr(C)]
#[derive(Debug)]
pub struct ProcessListInfo {
    pub pids: usize,
}

// Stores information about the target process
#[repr(C)]
#[derive(Debug, Default)]
pub struct TargetProcess {
    pub pid: usize,
}

// Process Info Hide
#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcessInfoHide {
    pub pid: usize,
    pub enable: bool,
}

// Signature information for the target process
#[repr(C)]
#[derive(Debug)]
pub struct ProcessSignature {
    pub pid: usize,
    pub sg: usize,
    pub tp: usize,
}

// Stores the process to be protected
#[repr(C)]
#[derive(Debug)]
pub struct ProcessProtection {
    pub pid: usize,
    pub enable: bool
}
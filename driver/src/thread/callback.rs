#![cfg(not(feature = "mapper"))]

use {
    alloc::vec::Vec, 
    core::ffi::c_void, 
    shared::{structs::{ThreadListInfo, ThreadProtection}, vars::MAX_TID}, 
    spin::{lazy::Lazy, Mutex}, 
    wdk_sys::{
        ntddk::PsGetThreadId, NTSTATUS, OB_PRE_OPERATION_INFORMATION, PETHREAD, 
        PVOID, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, THREAD_GET_CONTEXT, 
        THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, THREAD_TERMINATE, 
        STATUS_DUPLICATE_OBJECTID, _OB_PREOP_CALLBACK_STATUS::{self, OB_PREOP_SUCCESS}
    }
};

/// Handle for the thread callback registration.
pub static mut CALLBACK_REGISTRATION_HANDLE_THREAD: PVOID = core::ptr::null_mut();

/// List of the target TIDs
static TARGET_TIDS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_TID))); 

/// Method to check if the action sent is to add or remove a tid from the list of protected threads
///
/// # Parameters
/// - `process`: Structure with information about the process that will be added or removed from the list of protected threads.
///
/// # Returns
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
pub fn add_remove_thread_toggle(process: *mut ThreadProtection) -> NTSTATUS {
    let tid = unsafe { (*process).tid };
    if unsafe { (*process).enable } {
        add_target_tid(tid)
    } else {
        remove_target_tid(tid)
    }
}

/// Method for adding the list of threads that will have anti-kill / dumping protection.
///
/// # Parameters
/// - `tid`: The identifier of the target process (tid) to be hidden.
///
/// # Returns
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
fn add_target_tid(tid: usize) -> NTSTATUS {
    let mut tids = TARGET_TIDS.lock();

    if tids.len() >= MAX_TID {
        log::error!("tid list is full");
        return STATUS_UNSUCCESSFUL;
    }

    if tids.contains(&tid) {
        log::warn!("tid {} already exists in the list", tid);
        return STATUS_DUPLICATE_OBJECTID;
    }

    tids.push(tid);

    STATUS_SUCCESS
}

/// Method for removing the list of threads that will have anti-kill / dumping protection.
///
/// # Parameters
/// - `tid`: The identifier of the target process (tid) to be hidden.
///
/// # Returns
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
///
fn remove_target_tid(tid: usize) -> NTSTATUS {
    let mut tids = TARGET_TIDS.lock();

    if tids.len() >= MAX_TID {
        log::error!("tid list is full");
        return STATUS_UNSUCCESSFUL;
    }

    if let Some(index) = tids.iter().position(|&x| x == tid) {
        tids.remove(index);
        STATUS_SUCCESS
    } else {
        log::error!("TID {} not found in the list", tid);
        STATUS_UNSUCCESSFUL
    }
}

/// Enumerate threads Protect.
///
/// # Parameters
/// - `info_process`: It is a parameter of type `Infothreads` that will send the threads that are currently protected.
/// - `information`: It is a parameter of type `usize` that will be updated with the total size of the filled `Infothreads` structures.
/// 
/// # Returns
/// - `NTSTATUS`: A status code indicating success or failure of the operation.
///
pub unsafe fn enumerate_protection_threads(info_process: *mut ThreadListInfo, information: &mut usize) -> NTSTATUS {
    let process_info = TARGET_TIDS.lock();
    let mut count = 0;
    for i in process_info.iter() {
        (*info_process.offset(count)).tids = *i;

        *information += core::mem::size_of::<ThreadListInfo>();
        count += 1;
    }

    STATUS_SUCCESS
}

/// Pre-operation callback for thread opening that modifies the desired access rights to prevent certain actions on specific threads.
///
/// # Parameters
/// - `_registration_context`: A pointer to the registration context (unused).
/// - `info`: A pointer to the `OB_PRE_OPERATION_INFORMATION` structure containing information about the operation.
///
/// # Returns
/// - `_OB_PREOP_CALLBACK_STATUS::Type`: A status code indicating the success of the pre-operation.
///
pub unsafe extern "C" fn on_pre_open_thread(
    _registration_context: *mut c_void,
    info: *mut OB_PRE_OPERATION_INFORMATION,
) -> _OB_PREOP_CALLBACK_STATUS::Type {
    if (*info).__bindgen_anon_1.__bindgen_anon_1.KernelHandle() == 1 {
        return OB_PREOP_SUCCESS;
    }

    let thread = (*info).Object as PETHREAD;
    let tid = PsGetThreadId(thread) as usize;
    let tids = TARGET_TIDS.lock();

    if tids.contains(&tid) {
        let mask = !(THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
        (*(*info).Parameters).CreateHandleInformation.DesiredAccess &= mask;
    }

    OB_PREOP_SUCCESS
}

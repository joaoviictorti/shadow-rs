use {
    alloc::vec::Vec, 
    spin::{lazy::Lazy, Mutex},
    common::structs::TargetThread,
    wdk_sys::{
        *,
        ntddk::PsGetThreadId, 
        _OB_PREOP_CALLBACK_STATUS::{
            Type, OB_PREOP_SUCCESS
        },
    }
};

pub struct ThreadCallback;

const MAX_TID: usize = 100;

/// Handle for the thread callback registration.
pub static mut CALLBACK_REGISTRATION_HANDLE_THREAD: *mut core::ffi::c_void = core::ptr::null_mut();

/// List of the target TIDs
static TARGET_TIDS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| 
    Mutex::new(Vec::with_capacity(MAX_TID))
); 

impl ThreadCallback {
    /// Method for adding the list of threads that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    /// 
    /// * `tid` - The identifier of the target process (tid) to be hidden.
    ///
    /// # Returns
    /// 
    /// * A status code indicating the success or failure of the operation.
    pub fn add_target_tid(tid: usize) -> NTSTATUS {
        let mut tids = TARGET_TIDS.lock();

        if tids.len() >= MAX_TID {
            return STATUS_QUOTA_EXCEEDED;
        }

        if tids.contains(&tid) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        tids.push(tid);

        STATUS_SUCCESS
    }

    /// Method for removing the list of threads that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    ///
    /// * `tid` - The identifier of the target process (tid) to be hidden.
    ///
    /// # Returns
    /// 
    /// * A status code indicating the success or failure of the operation.
    pub fn remove_target_tid(tid: usize) -> NTSTATUS {
        let mut tids = TARGET_TIDS.lock();

        if let Some(index) = tids.iter().position(|&x| x == tid) {
            tids.remove(index);
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }

    /// Enumerate threads Protect.
    ///
    /// # Arguments
    /// 
    /// * `info_process` - It is a parameter of type `Infothreads` that will send the threads that are currently protected.
    /// * `information` - It is a parameter of type `usize` that will be updated with the total size of the filled `Infothreads` structures.
    /// 
    /// # Returns
    /// 
    /// * A status code indicating success or failure of the operation.
    pub unsafe fn enumerate_protection_thread() -> Vec<TargetThread> {
        let mut threads: Vec<TargetThread> = Vec::new();
        let thread_info = TARGET_TIDS.lock();
        for i in thread_info.iter() {
            threads.push(TargetThread {
                tid: *i,
                ..Default::default()
            });
        }

        threads
    }

    /// Pre-operation callback for thread opening that modifies the desired access rights to prevent certain actions on specific threads.
    ///
    /// # Arguments
    /// 
    /// * `_registration_context` - A pointer to the registration context (unused).
    /// * `info` - A pointer to the `OB_PRE_OPERATION_INFORMATION` structure containing information about the operation.
    ///
    /// # Returns
    /// 
    /// * A status code indicating the success of the pre-operation.
    pub unsafe extern "C" fn on_pre_open_thread(
        _registration_context: *mut core::ffi::c_void,
        info: *mut OB_PRE_OPERATION_INFORMATION,
    ) -> Type {
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
}


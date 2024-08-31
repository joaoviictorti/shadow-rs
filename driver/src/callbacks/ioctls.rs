use {
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{
        ioctls::{IOCTL_ENUMERATE_CALLBACK, IOCTL_ENUMERATE_REMOVED_CALLBACK, IOCTL_REMOVE_CALLBACK, IOCTL_RESTORE_CALLBACK}, 
        structs::{CallbackInfoInput, CallbackInfoOutput}
    },
    wdk_sys::{IO_STACK_LOCATION, IRP},
    crate::{handle_callback, utils::ioctls::IoctlHandler},
};

pub fn get_callback_ioctls(ioctls: &mut HashMap<u32, IoctlHandler> ) {

    // Lists callbacks.
    ioctls.insert(IOCTL_ENUMERATE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENUMERATE_CALLBACK");
        let mut information = 0;
        let status = unsafe { handle_callback!(irp, stack, CallbackInfoInput, CallbackInfoOutput, &mut information, IOCTL_ENUMERATE_CALLBACK) };
        unsafe { (*irp).IoStatus.Information = information as u64 };
        status
    }) as IoctlHandler);

    // ?
    ioctls.insert(IOCTL_ENUMERATE_REMOVED_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENUMERATE_REMOVED_CALLBACK");
        let mut information = 0;
        let status = unsafe { handle_callback!(irp, stack, CallbackInfoInput, CallbackInfoOutput, &mut information, IOCTL_ENUMERATE_REMOVED_CALLBACK) };
        unsafe { (*irp).IoStatus.Information = information as u64 };
        status
    }) as IoctlHandler);

    // Remove a callback.
    ioctls.insert(IOCTL_REMOVE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_REMOVE_CALLBACK");
        let status = unsafe { handle_callback!(stack, CallbackInfoInput, IOCTL_REMOVE_CALLBACK) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // ?
    ioctls.insert(IOCTL_RESTORE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_RESTORE_CALLBACK");
        let status = unsafe { handle_callback!(stack, CallbackInfoInput, IOCTL_RESTORE_CALLBACK) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);
}
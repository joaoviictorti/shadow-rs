#![no_std]
#![allow(unused_must_use)]
#![allow(static_mut_refs)]

extern crate alloc;
extern crate wdk_panic;

mod utils;
mod ioctls;
mod allocator;

#[cfg(not(feature = "mapper"))]
mod callback;

#[cfg(not(feature = "mapper"))]
use callback::{
    DRIVER_BASE, DRIVER_SIZE, 
    Callback
};

use spin::{Mutex, lazy::Lazy};
use core::sync::atomic::Ordering;
use shadowx::{uni, error::ShadowError, network, Network};
use wdk_sys::{*, ntddk::*, _MODE::KernelMode};

/// The name of the device in the device namespace.
const DEVICE_NAME: &str = "\\Device\\shadow";

/// The name of the device in the DOS device namespace.
const DOS_DEVICE_NAME: &str = "\\DosDevices\\shadow";

/// Driver input function.
///
/// This function is called by the system when the driver is loaded.
///
/// # Arguments
/// 
/// * `driver_object` - Pointer to the driver object.
/// * `registry_path` - Pointer to the Unicode string that specifies the driver's registry path.
///
/// # Returns
/// 
/// * Status code indicating the success or failure of the operation.
///
/// Reference: WDF expects a symbol with the name DriverEntry
#[export_name = "DriverEntry"]
#[link_section = "INIT"]
pub unsafe extern "system" fn driver_entry(
    _driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    kernel_log::KernelLogger::init(log::LevelFilter::Info).expect("Failed to initialize logger");

    #[cfg(feature = "mapper")] {
        use shadowx::IoCreateDriver;

        const DRIVER_NAME: &str = "\\Driver\\shadow";
        let mut driver_name = uni::str_to_unicode(DRIVER_NAME).to_unicode();
        let status = IoCreateDriver(&mut driver_name, Some(shadow_entry));
        if !NT_SUCCESS(status) {
            log::error!("IoCreateDriver Failed With Status: {status}");
        }

        return status;
    }

    #[cfg(not(feature = "mapper"))]
    shadow_entry(_driver, _registry_path)
}

/// Driver input function.
///
/// This function is called by the system when the driver is loaded. It is responsible for
/// initializing the driver, creating the device object and setting up the symbolic link.
///
/// # Arguments
/// 
/// * `driver_object` - Pointer to the driver object.
/// * `_registry_path` - Pointer to the Unicode string that specifies the driver's registry path.
///
/// # Returns
/// 
/// * Status code indicating the success or failure of the operation. 
pub unsafe extern "system" fn shadow_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    log::info!("Shadow Loaded");

    let device_name = uni::str_to_unicode(DEVICE_NAME);
    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME);
    let mut device_object = core::ptr::null_mut();
    let mut status = IoCreateDevice(
        driver,
        0,
        &mut device_name.to_unicode(),
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        0,
        &mut device_object,
    );

    if !NT_SUCCESS(status) {
        log::error!("IoCreateDevice Failed With Status: {status}");
        return status;
    }

    driver.DriverUnload = Some(driver_unload);
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(driver_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(driver_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(device_control);

    status = IoCreateSymbolicLink(&mut dos_device_name.to_unicode(), &mut device_name.to_unicode());
    if !NT_SUCCESS(status) {
        IoDeleteDevice(device_object);
        log::error!("IoCreateSymbolicLink Failed With Status: {status}");
        return status;
    }

    #[cfg(feature = "mapper")] {
        (*device_object).Flags |= DO_BUFFERED_IO;
        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
    }

    #[cfg(not(feature = "mapper"))] {
        // Initialize the driver base address and size
        DRIVER_BASE = driver.DriverStart;
        DRIVER_SIZE = driver.DriverSize;
        
        // Initialize Callbacks
        status = Callback::new(driver).register();
        if !NT_SUCCESS(status) {
            IoDeleteDevice(device_object);
            IoDeleteSymbolicLink(&mut dos_device_name.to_unicode());
            log::error!("Callback Failed With Status: {status}");
            return status;
        }
    }

    STATUS_SUCCESS
}

// Global instance of the `IoctlManager`.
//
// This `lazy_static` ensures that the `IoctlManager` is initialized only once
// and provides a thread-safe way to access the registered IOCTL handlers.
static mut MANAGER: Lazy<Mutex<ioctls::IoctlManager>> = Lazy::new(|| { 
    let manager = Mutex::new(ioctls::IoctlManager::default());
    manager.lock().load_handlers();
    manager
});

/// Handles device control commands (IOCTL).
///
/// This function is responsible for processing IOCTL commands received by the driver and executing the corresponding actions.
///
/// # Arguments
/// 
/// * `_device` - Pointer to the device object (not used in this function).
/// * `irp` - Pointer to the I/O request packet (IRP) that contains the information about the device control request.
///
/// # Returns
/// 
/// * Status code indicating the success or failure of the operation.
pub unsafe extern "C" fn device_control(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    let stack = (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation;
    let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;
    
    let status = if let Some(handler) = MANAGER.lock().get_handler(control_code) {
        handler(irp, stack)
    } else {
        Err(ShadowError::InvalidDeviceRequest)
    };

    let status = match status {
        Ok(ntstatus) => ntstatus,
        Err(err) => {
            log::error!("Error: {err}");
            STATUS_INVALID_DEVICE_REQUEST
        },
    };

    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);

    status
}

/// Closes an open instance of the device.
///
/// This function is called when an open instance of the device is closed.
/// It marks the I/O request (IRP) as successfully completed.
///
/// # Arguments
/// 
/// * `_device_object` - Pointer to the associated device object (not used in this function).
/// * `irp` - Pointer to the I/O request packet (IRP) containing the information about the close request.
///
/// # Returns
/// 
/// * Status code indicating the success of the operation (always returns `STATUS_SUCCESS`).
pub unsafe extern "C" fn driver_close(_device_object: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    (*irp).IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);

    STATUS_SUCCESS
}

/// Download the system driver.
///
/// This function is called when the driver is being unloaded from the system.
/// It removes the symbolic link and deletes the device object associated with the driver.
///
/// # Arguments
/// 
/// * `driver_object` - Pointer to the driver object being unloaded.
pub unsafe extern "C" fn driver_unload(driver_object: *mut DRIVER_OBJECT) {
    log::info!("Unloading driver");

    if network::HOOK_INSTALLED.load(Ordering::Relaxed) {
        Network::uninstall_hook();
        let mut interval = LARGE_INTEGER {
            QuadPart: -50 * 1000_i64 * 1000_i64,
        };
    
        KeDelayExecutionThread(KernelMode as i8, 0, &mut interval);    
    }

    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&mut dos_device_name.to_unicode());
    IoDeleteDevice((*driver_object).DeviceObject);

    #[cfg(not(feature = "mapper"))] {
        Callback::unload();
    }

    log::info!("Shadow Unload");
}

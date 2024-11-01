#![no_std]
#![allow(unused_must_use)]
#![allow(unused_variables)]
#![allow(static_mut_refs)]

extern crate alloc;

use {
    utils::uni, 
    log::{error, info}, 
    kernel_log::KernelLogger, 
    shadowx::error::ShadowError, 
    crate::utils::ioctls::IoctlManager,
    wdk_sys::{*, ntddk::*, _MODE::KernelMode},
    core::{ptr::null_mut, sync::atomic::Ordering}, 
};

#[cfg(not(feature = "mapper"))]
use shadowx::{
    ThreadCallback, CALLBACK_REGISTRATION_HANDLE_THREAD,
    ProcessCallback, CALLBACK_REGISTRATION_HANDLE_PROCESS,
    registry::callback::{CALLBACK_REGISTRY, registry_callback}
};

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: wdk_alloc::WDKAllocator = wdk_alloc::WDKAllocator;

mod modules;
mod utils;

/// The name of the device in the device namespace.
const DEVICE_NAME: &str = "\\Device\\shadow";

/// The name of the device in the DOS device namespace.
const DOS_DEVICE_NAME: &str = "\\??\\shadow";

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
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    KernelLogger::init(log::LevelFilter::Info).expect("Failed to initialize logger");
    
    #[cfg(feature = "mapper")] {
        use shadowx::data::IoCreateDriver;

        const DRIVER_NAME: &str = "\\Driver\\shadow";
        let mut driver_name = uni::str_to_unicode(DRIVER_NAME).to_unicode();
        let status = IoCreateDriver(&mut driver_name, Some(shadow_entry));
        if !NT_SUCCESS(status) {
            error!("IoCreateDriver Failed With Status: {status}");
        }
        return status;
    }

    shadow_entry(driver, registry_path)
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
    info!("Shadow Loaded");

    let device_name = uni::str_to_unicode(DEVICE_NAME);
    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME);
    let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
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
        error!("IoCreateDevice Failed With Status: {status}");
        return status;
    }

    driver.DriverUnload = Some(driver_unload);
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(driver_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(driver_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(device_control);

    status = IoCreateSymbolicLink(&mut dos_device_name.to_unicode(),&mut device_name.to_unicode());

    if !NT_SUCCESS(status) {
        IoDeleteDevice(device_object);
        error!("IoCreateSymbolicLink Failed With Status: {status}");
        return status;
    }

    #[cfg(feature = "mapper")] {
        (*device_object).Flags |= DO_BUFFERED_IO;
        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
    }

    #[cfg(not(feature = "mapper"))] {
        status = register_callbacks(driver);
        if !NT_SUCCESS(status) {
            error!("register_callbacks Failed With Status: {status}");
            return status;
        }
    }

    STATUS_SUCCESS
}

lazy_static::lazy_static! {
    pub static ref MANAGER: IoctlManager = {
        let mut manager = IoctlManager::default();
        manager.load_default_handlers();
        manager
    };
}

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
    
    let status = if let Some(handler) = MANAGER.get_handler(control_code) {
        handler(irp, stack)
    } else {
        Err(ShadowError::InvalidDeviceRequest)
    };

    let status = match status {
        Ok(ntstatus) => ntstatus,
        Err(err) => {
            error!("Error: {err}");
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
    info!("Unloading driver");

    if shadowx::port::HOOK_INSTALLED.load(Ordering::Relaxed) {
        let hook_status = shadowx::Port::uninstall_hook();
        let mut interval = LARGE_INTEGER {
            QuadPart: -50 * 1000_i64 * 1000_i64,
        };
    
        KeDelayExecutionThread(KernelMode as i8, 0, &mut interval);    
    }

    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&mut dos_device_name.to_unicode());
    IoDeleteDevice((*driver_object).DeviceObject);

    #[cfg(not(feature = "mapper"))] {
        ObUnRegisterCallbacks(CALLBACK_REGISTRATION_HANDLE_PROCESS);
        ObUnRegisterCallbacks(CALLBACK_REGISTRATION_HANDLE_THREAD);
        CmUnRegisterCallback(CALLBACK_REGISTRY);
    }

    info!("Shadow Unload");
}

/// Register Callbacks.
///
/// # Arguments
/// 
/// * `driver_object` - Pointer to the driver object being unloaded.
/// 
/// # Returns
/// 
/// * Status code indicating the success of the operation (always returns `STATUS_SUCCESS`).
#[cfg(not(feature = "mapper"))]
pub unsafe fn register_callbacks(driver_object: &mut DRIVER_OBJECT) -> NTSTATUS {
    // Creating callbacks related to Process operations
    let altitude = uni::str_to_unicode("31243.5222");
    let mut op_reg = OB_OPERATION_REGISTRATION {
        ObjectType: PsProcessType,
        Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        PreOperation: Some(ProcessCallback::on_pre_open_process),
        PostOperation: None,
    };
    let mut cb_reg = OB_CALLBACK_REGISTRATION {
        Version: OB_FLT_REGISTRATION_VERSION as u16,
        OperationRegistrationCount: 1,
        Altitude: altitude.to_unicode(),
        RegistrationContext: core::ptr::null_mut(),
        OperationRegistration: &mut op_reg,
    };

    let mut status = ObRegisterCallbacks(&mut cb_reg,core::ptr::addr_of_mut!(CALLBACK_REGISTRATION_HANDLE_PROCESS));
    if !NT_SUCCESS(status) {
        error!("ObRegisterCallbacks (Process) Failed With Status: {status}");
        return status;
    }

    // Creating callbacks related to thread operations
    let altitude = uni::str_to_unicode("31243.5223");
    let mut op_reg = OB_OPERATION_REGISTRATION {
        ObjectType: PsThreadType,
        Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        PreOperation: Some(ThreadCallback::on_pre_open_thread),
        PostOperation: None,
    };
    let mut cb_reg = OB_CALLBACK_REGISTRATION {
        Version: OB_FLT_REGISTRATION_VERSION as u16,
        OperationRegistrationCount: 1,
        Altitude: altitude.to_unicode(),
        RegistrationContext: core::ptr::null_mut(),
        OperationRegistration: &mut op_reg,
    };

    status = ObRegisterCallbacks(&mut cb_reg,core::ptr::addr_of_mut!(CALLBACK_REGISTRATION_HANDLE_THREAD));
    if !NT_SUCCESS(status) {
        error!("ObRegisterCallbacks (Thread) Failed With Status: {status}");
        return status;
    }

    // Creating callbacks related to registry operations
    let mut altitude = uni::str_to_unicode("31422.6172").to_unicode();
    status = CmRegisterCallbackEx(
        Some(registry_callback),
        &mut altitude,
        driver_object as *mut DRIVER_OBJECT as *mut core::ffi::c_void,
        null_mut(),
        core::ptr::addr_of_mut!(CALLBACK_REGISTRY),
        null_mut(),
    );

    if !NT_SUCCESS(status) {
        error!("CmRegisterCallbackEx Failed With Status: {status}");
        return status;
    }

    status
}

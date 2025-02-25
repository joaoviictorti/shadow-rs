use crate::utils::open_driver;
use common::structs::TargetRegistry;
use std::{ffi::c_void, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::IO::DeviceIoControl,
};

/// Provides operations for managing the registry through a driver interface.
pub struct Registry {
    driver_handle: HANDLE,
}

impl Registry {
    /// Creates a new `Registry` instance, opening a handle to the driver.
    ///
    /// # Returns
    ///
    /// * An instance of `Registry`.
    ///
    /// # Panics
    ///
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Error");
        Registry { driver_handle }
    }

    /// Enables or disables protection for a specified registry key and value.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the protection operation.
    /// * `value` - A reference to the registry value name to protect.
    /// * `key` - A reference to the registry key name to protect.
    /// * `enable` - `true` to enable protection or `false` to disable it.
    pub fn registry_protection(self, ioctl_code: u32, value: &String, key: &String, enable: bool) {
        log::info!("Attempting to open the registry for protection operation");
        log::debug!("Preparing structure for Key: {key} | Value: {value} | Protection: {}", if enable { "hide" } else { "unhide" });
        let mut info_registry = TargetRegistry {
            enable,
            value: value.to_string(),
            key: key.to_string(),
        };

        log::debug!("Sending DeviceIoControl command to {} protection for key: {key} | value: {value}", if enable { "enable" } else { "disable" });
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
            log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            log::info!("Registry protection {} for Key: {key} and Value: {value} succeeded", if enable { "enabled" } else { "disabled" });
        }
    }

    /// Hides or unhides a specified registry key and value.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the hide/unhide operation.
    /// * `value` - A reference to the registry value name to hide/unhide.
    /// * `key` - A reference to the registry key name to hide/unhide.
    /// * `enable` - `true` to hide or `false` to unhide.
    pub fn registry_hide_unhide(self, ioctl_code: u32, value: &String, key: &String, enable: bool) {
        log::info!("Attempting to open the registry for hide/unhide operation");

        log::debug!("Preparing structure for Key: {key} | Value: {value} | Operation: {}", if enable { "hide" } else { "unhide" });
        let mut info_registry = TargetRegistry {
            enable,
            key: key.to_string(),
            value: value.to_string(),
            ..Default::default()
        };

        log::debug!("Sending DeviceIoControl command to {} registry for Key: {key} | Value: {value}", if enable { "hide" } else { "unhide" });
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
            log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            log::info!("Registry with Key: {key} and Value: {value} successfully {}hidden", if enable { "" } else { "un" });
        }
    }
}

impl Drop for Registry {
    /// Ensures the driver handle is closed when `Registry` goes out of scope.
    fn drop(&mut self) {
        log::debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

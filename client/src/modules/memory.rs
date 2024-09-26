use std::ptr::null_mut;
use windows_sys::Win32::System::IO::DeviceIoControl;
use crate::modules::driver::open_driver;

pub fn enumerate_pool(ioctl_code: u32) {
    let h_file = open_driver().expect("Failed open driver");
    let status;
    let mut return_buffer = 0;
    status = unsafe { 
        DeviceIoControl(
            h_file,
            ioctl_code,
            null_mut(),
            0,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Enumerate Module start");
    }
}

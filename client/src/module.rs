use {
    crate::driver::open_driver,
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    shared::structs::{ModuleInfo, TargetProcess},
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl},
};

pub fn enumerate_module(ioctl_code: u32, pid: &u32) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut module_info: [ModuleInfo; 400] = unsafe { std::mem::zeroed() };
    let mut input_module = TargetProcess {
        pid: *pid as usize
    };
    let mut return_buffer = 0;
    let status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut input_module  as *mut _ as *mut c_void,
            size_of::<TargetProcess>() as u32,
            module_info.as_mut_ptr() as *mut _,
            (module_info.len() * size_of::<ModuleInfo>()) as u32,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        let total_module = return_buffer as usize / size_of::<ModuleInfo>();
        println!("[+] Total modules: {}", total_module);
        for i in module_info.iter() {
            if i.address > 0 {
                let name = match String::from_utf16(&i.name) {
                  Ok(name) => name,
                  Err(err) => {
                    eprintln!("[!] UTF-16 decoding error: {:?}", err);
                    continue;
                  }  
                };
                println!("[{}] {:?} {}", i.index, i.address as *mut c_void, name);
            }
        }
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

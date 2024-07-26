use {
    crate::{cli::Callbacks, driver::open_driver},
    std::{ptr::null_mut, mem::size_of, ffi::c_void},
    shared::structs::{CallbackInfoInput, CallbackInfoOutput},
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl},
};

pub fn enumerate_callback(ioctl_code: u32, callback: &Callbacks) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut return_buffer = 0;
    let mut callback_info: [CallbackInfoOutput; 400] = unsafe { std::mem::zeroed() };
    let mut input_callback = CallbackInfoInput {
        index: 0,
        callback: callback.to_shared()
    };

    let status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut input_callback  as *mut _ as *mut c_void,
            size_of::<CallbackInfoInput>() as u32,
            callback_info.as_mut_ptr() as *mut _,
            (callback_info.len() * size_of::<CallbackInfoOutput>()) as u32,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        let total_module = return_buffer as usize / size_of::<CallbackInfoOutput>();
        println!("[+] Total modules: {}", total_module);
        for i in callback_info.iter() {
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

pub fn remove_callback(index: usize, ioctl_code: u32, callback: &Callbacks) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut callback_info =  CallbackInfoInput {
        index,
        callback: callback.to_shared()
    };
    let mut return_buffer = 0;
    let status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut callback_info  as *mut _ as *mut c_void,
            size_of::<CallbackInfoInput>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Remove Callback: {index}");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn restore_callback(index: usize, ioctl_code: u32, callback: &Callbacks) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut callback_info =  CallbackInfoInput {
        index,
        callback: callback.to_shared()
    };
    let mut return_buffer = 0;
    let status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut callback_info  as *mut _ as *mut c_void,
            size_of::<CallbackInfoInput>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Restore Callback: {index}");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

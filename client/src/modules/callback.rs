use {
    crate::{cli::Callbacks, utils::open_driver},
    shared::structs::{CallbackInfoInput, CallbackInfoOutput}, 
    std::{ffi::c_void, mem::size_of, ptr::null_mut}, 
    windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError}, 
        System::IO::DeviceIoControl
    }
};

pub fn enumerate_callback(ioctl_code: u32, callback: &Callbacks) {
    log::debug!("Attempting to open the driver for callback enumeration");
    let h_file = open_driver().expect("Failed to open driver");

    log::debug!("Allocating memory for callback information");
    let mut return_buffer = 0;
    let mut callback_info: [CallbackInfoOutput; 400] = unsafe { std::mem::zeroed() };
    let mut input_callback = CallbackInfoInput {
        index: 0,
        callback: callback.to_shared()
    };

    log::debug!("Sending DeviceIoControl command to enumerate callbacks");
    let status = unsafe { 
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut input_callback as *mut _ as *mut c_void,
            size_of::<CallbackInfoInput>() as u32,
            callback_info.as_mut_ptr() as *mut _,
            (callback_info.len() * size_of::<CallbackInfoOutput>()) as u32,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        let total_modules = return_buffer as usize / size_of::<CallbackInfoOutput>();
        log::info!("Total callbacks found: {}", total_modules);
        log::info!("Listing callbacks:");
        println!("");

        for i in callback_info.iter() {
            if i.address > 0 {
                let name = match String::from_utf16(&i.name) {
                    Ok(name) => name.trim_end_matches('\0').to_string(),
                    Err(err) => {
                        log::error!("UTF-16 decoding error: {:?}", err);
                        continue;
                    }
                };
                println!("[{}] {:?} {}", i.index, i.address as *mut c_void, name);
            } else if i.post_operation > 0 || i.pre_operation > 0 {
                let name = match String::from_utf16(&i.name) {
                    Ok(name) => name.trim_end_matches('\0').to_string(),
                    Err(err) => {
                        log::error!("UTF-16 decoding error: {:?}", err);
                        continue;
                    }
                };
                println!("[{}] {}", i.index, name);
                println!("\tpre_operation: {:?}", i.pre_operation as *mut c_void);
                println!("\tpost_operation: {:?}", i.post_operation as *mut c_void);
            }
        }
        println!("");
        log::info!("Callback enumeration completed")
    }

    log::debug!("Closing the driver handle");
    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn remove_callback(index: usize, ioctl_code: u32, callback: &Callbacks) {
    log::debug!("Attempting to open the driver to remove callback at index: {}", index);
    let h_file = open_driver().expect("Failed to open driver");

    log::debug!("Preparing structure to remove callback at index: {}", index);   
    let mut callback_info = CallbackInfoInput {
        index,
        callback: callback.to_shared()
    };

    log::debug!("Sending DeviceIoControl command to remove callback at index: {}", index);
    let mut return_buffer = 0;
    let status = unsafe { 
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut callback_info as *mut _ as *mut c_void,
            size_of::<CallbackInfoInput>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        log::info!("Successfully removed callback at index: {}", index);
    }

    log::debug!("Closing the driver handle");
    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn restore_callback(index: usize, ioctl_code: u32, callback: &Callbacks) {
    log::debug!("Attempting to open the driver to restore callback at index: {}", index);
    let h_file = open_driver().expect("Failed to open driver");

    log::debug!("Preparing structure to restore callback at index: {}", index);    
    let mut callback_info = CallbackInfoInput {
        index,
        callback: callback.to_shared()
    };

    log::debug!("Sending DeviceIoControl command to restore callback at index: {}", index);
    let mut return_buffer = 0;
    let status = unsafe { 
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut callback_info as *mut _ as *mut c_void,
            size_of::<CallbackInfoInput>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        log::info!("Successfully restored callback at index: {}", index);
    }

    log::debug!("Closing the driver handle");
    unsafe { 
        CloseHandle(h_file);
    };
}

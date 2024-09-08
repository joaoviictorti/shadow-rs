use std::{path::Path, ptr::null_mut};
use windows_sys::{
    w, 
    Win32::{
        Foundation::{GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE}, 
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING}
    }
};

pub fn check_file(file: &String) -> bool {
    let file = Path::new(file);
    file.exists()
}

pub fn open_driver() -> Result<HANDLE, ()> {
    log::info!("Opening driver handle");
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
        log::error!("CreateFileW failed with error: {:?}", unsafe { GetLastError() });
        return Err(());
    }

    log::info!("Driver handle successfully opened");
    Ok(h_file)
}

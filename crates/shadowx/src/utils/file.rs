use {
    alloc::vec::Vec,
    crate::error::ShadowError,
    core::{ffi::c_void, ptr::null_mut},
    super::{handle::Handle, InitializeObjectAttributes},
    wdk_sys::{
        *, 
        ntddk::*, 
        _FILE_INFORMATION_CLASS::FileStandardInformation
    },
};

/// Reads the content of a file given its path in the NT kernel environment.
/// 
/// This function opens a file specified by the given path, reads its content, 
/// and returns the data as a vector of bytes. It uses the `ZwCreateFile` function 
/// to open the file and `ZwReadFile` to read its content. The path is automatically
/// converted to NT format (e.g., `\\??\\C:\\path\\to\\file`).
///
/// # Arguments
/// 
/// * `path` - A string slice representing the path to the file. The path should follow 
///   the standard Windows format (e.g., `C:\\path\\to\\file`).
/// 
/// # Returns
///
/// * `Ok(Vec<u8>)` - A vector containing the file's content as bytes if the file is successfully opened and read.
/// * `Err(ShadowError)` - If an error occurs during:
///     - Opening the file (`ZwCreateFile` failure),
///     - Querying file information (`ZwQueryInformationFile` failure),
///     - Reading the file (`ZwReadFile` failure).
pub fn read_file(path: &str) -> Result<Vec<u8>, ShadowError> {
    // Converts the path to NT format (e.g., "\\??\\C:\\path\\to\\file")
    let path_nt = alloc::format!("\\??\\{}", path);

    // Converts the NT path to a Unicode string
    let file_name = crate::utils::uni::str_to_unicode(&path_nt);
    
    // Initializes the object attributes for opening the file, including setting
    // it as case insensitive and kernel-handled
    let mut io_status_block: _IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    let mut obj_attr = InitializeObjectAttributes(
        Some(&mut file_name.to_unicode()), 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
        None, 
        None, 
        None
    );

    // Opens the file using ZwCreateFile with read permissions
    let mut h_file: HANDLE = null_mut();
    let mut status = unsafe { 
        ZwCreateFile(
            &mut h_file,
            GENERIC_READ,
            &mut obj_attr,
            &mut io_status_block,
            null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut(),
            0,
        )
    };

    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed("ZwCreateFile", status));
    }

    // Wrap the file handle in a safe Handle type
    let h_file = Handle::new(h_file);

    // Placeholder for storing file information (e.g., size)
    let mut file_info: FILE_STANDARD_INFORMATION = unsafe { core::mem::zeroed() };

    // Queries file information, such as its size, using ZwQueryInformationFile
    status = unsafe { 
        ZwQueryInformationFile(
            h_file.get(), 
            &mut io_status_block, 
            &mut file_info as *mut _ as *mut c_void, 
            size_of::<FILE_STANDARD_INFORMATION>() as u32, 
            FileStandardInformation
        )
    };

    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed("ZwQueryInformationFile", status));
    }

    // Retrieves the file size from the queried file information
    let file_size = unsafe { file_info.EndOfFile.QuadPart as usize };
    
    // Initializes the byte offset to 0 for reading from the beginning of the file
    let mut byte_offset: LARGE_INTEGER = unsafe { core::mem::zeroed() };
    byte_offset.QuadPart = 0;
    
    // Reads the file content into the buffer using ZwReadFile
    let mut shellcode = alloc::vec![0u8; file_size];
    status = unsafe { 
        ZwReadFile(
            h_file.get(),
            null_mut(),
            None,
            null_mut(),
            &mut io_status_block,
            shellcode.as_mut_ptr() as *mut c_void,
            file_size as u32,
            &mut byte_offset,
            null_mut()
        )
    };

    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed("ZwReadFile", status));
    }

    // Returns the file content as a vector of bytes if everything succeeds
    Ok(shellcode)
}
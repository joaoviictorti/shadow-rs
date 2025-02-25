use wdk_sys::{_IO_STACK_LOCATION, IRP};
use shadowx::error::ShadowError;

/// Retrieves the input buffer from the given IO stack location.
///
/// # Arguments
/// 
/// * `stack` - A pointer to the `_IO_STACK_LOCATION` structure.
///
/// # Returns
/// 
/// * `Result<*mut T, ShadowError>` - A result containing the pointer to the input buffer or an NTSTATUS error code.
pub unsafe fn get_input_buffer<T>(stack: *mut _IO_STACK_LOCATION) -> Result<*mut T, ShadowError> {
    let buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer;
    let length = (*stack).Parameters.DeviceIoControl.InputBufferLength;
    
    if buffer.is_null() {
        return Err(ShadowError::NullPointer("Type3InputBuffer"))
    } 
    
    if length < size_of::<T>() as u32 {
        return Err(ShadowError::BufferTooSmall);
    }

    Ok(buffer as *mut T)
}

/// Retrieves the output buffer from the given IRP.
///
/// # Arguments
/// 
/// * `irp` - A pointer to the `IRP` structure.
///
/// # Returns
/// 
/// * `Result<*mut T, ShadowError>` - A result containing the pointer to the output buffer or an NTSTATUS error code.
pub unsafe fn get_output_buffer<T>(irp: *mut IRP) -> Result<*mut T, ShadowError> {
    let buffer = (*irp).UserBuffer;
    if buffer.is_null() {
        return Err(ShadowError::NullPointer("UserBuffer"));
    }

    Ok(buffer as *mut T)
}

use shadowx::error::ShadowError;
use wdk_sys::*;
use core::mem::size_of;

pub mod uni;
pub mod ioctls;

/// Retrieves the input buffer from the given IO stack location.
///
/// # Arguments
/// 
/// * `stack` - A pointer to the `_IO_STACK_LOCATION` structure.
///
/// # Returns
/// 
/// * `Result<*mut T, NTSTATUS>` - A result containing the pointer to the input buffer or an NTSTATUS error code.
pub unsafe fn get_input_buffer<T>(stack: *mut _IO_STACK_LOCATION) -> Result<*mut T, ShadowError> {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer;
    let input_buffer_length = (*stack).Parameters.DeviceIoControl.InputBufferLength;
    
    if input_buffer.is_null() {
        return Err(ShadowError::NullPointer("Type3InputBuffer"))
    } 
    
    if input_buffer_length < size_of::<T>() as u32 {
        return Err(ShadowError::BufferTooSmall);
    }

    Ok(input_buffer as *mut T)
}

/// Retrieves the output buffer from the given IRP.
///
/// # Arguments
/// 
/// * `irp` - A pointer to the `IRP` structure.
///
/// # Returns
/// 
/// * `Result<*mut T, NTSTATUS>` - A result containing the pointer to the output buffer or an NTSTATUS error code.
pub unsafe fn get_output_buffer<T>(irp: *mut IRP) -> Result<*mut T, ShadowError> {
    let output_buffer = (*irp).UserBuffer;
    let output_buffer_length = (*irp).IoStatus.Information as usize;

    if output_buffer.is_null() {
        return Err(ShadowError::NullPointer("UserBuffer"));
    }

    Ok(output_buffer as *mut T)
}

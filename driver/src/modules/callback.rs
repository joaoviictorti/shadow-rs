use {
    alloc::boxed::Box,
    wdk_sys::{IO_STACK_LOCATION, IRP, STATUS_SUCCESS},
};

use {
    crate::utils::{
        ioctls::IoctlManager,
        get_input_buffer, get_output_buffer,
    }, 
    common::{
        enums::Callbacks,
        structs::{CallbackInfoInput, CallbackInfoOutput},
        ioctls::{
            REMOVE_CALLBACK, RESTORE_CALLBACK,
            ENUMERATE_CALLBACK, ENUMERATE_REMOVED_CALLBACK, 
        }, 
    },
};

/// Registers the IOCTL handlers for callback-related operations.
///
/// This function inserts two IOCTL handlers into the provided `HashMap`, associating them with
/// their respective IOCTL codes. The two operations supported are:
///
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to a `HashMap<u32, IoctlHandler>` where the callback-related
///   IOCTL handlers will be inserted.
pub fn register_callback_ioctls(ioctls: &mut IoctlManager) {
    // Lists Callbacks.
    ioctls.register_handler(ENUMERATE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
            let callback_info = get_output_buffer::<CallbackInfoOutput>(irp)?;
            let callbacks = match (*target_callback).callback {
                Callbacks::PsSetCreateProcessNotifyRoutine 
                | Callbacks::PsSetCreateThreadNotifyRoutine
                | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::enumerate((*target_callback).callback)?,
                
                Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::enumerate((*target_callback).callback)?,
                
                Callbacks::ObProcess
                | Callbacks::ObThread => shadowx::CallbackOb::enumerate((*target_callback).callback)?,
            };

            for (index, callback) in callbacks.iter().enumerate() {
                let info_ptr = callback_info.add(index);
                
                core::ptr::copy_nonoverlapping(callback.name.as_ptr(), (*info_ptr).name.as_mut_ptr(), callback.name.len());
                (*info_ptr).address = callback.address;
                (*info_ptr).index = index as u8;
                (*info_ptr).pre_operation = callback.pre_operation;
                (*info_ptr).post_operation = callback.post_operation;
            }

            // Set the size of the returned information.
            (*irp).IoStatus.Information = (callbacks.len() * size_of::<CallbackInfoOutput>()) as u64;
            Ok(STATUS_SUCCESS)
        }
    }));

    // Remove Callback.
    ioctls.register_handler(REMOVE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
            let status = match (*target_callback).callback {
                Callbacks::PsSetCreateProcessNotifyRoutine 
                | Callbacks::PsSetCreateThreadNotifyRoutine
                | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::remove((*target_callback).callback, (*target_callback).index)?,
                
                Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::remove((*target_callback).callback, (*target_callback).index)?,
                
                Callbacks::ObProcess
                | Callbacks::ObThread => shadowx::CallbackOb::remove((*target_callback).callback, (*target_callback).index)?,
            };

            // Set the size of the returned information.
            (*irp).IoStatus.Information = size_of::<CallbackInfoInput>() as u64;
            Ok(status)
        }
    }));

    // Restore Callback.
    ioctls.register_handler(RESTORE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
            let status = match (*target_callback).callback {
                Callbacks::PsSetCreateProcessNotifyRoutine 
                | Callbacks::PsSetCreateThreadNotifyRoutine
                | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::restore((*target_callback).callback, (*target_callback).index)?,
                
                Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::restore((*target_callback).callback, (*target_callback).index)?,
                
                Callbacks::ObProcess
                | Callbacks::ObThread => shadowx::CallbackOb::restore((*target_callback).callback, (*target_callback).index)?,
            };

            // Set the size of the returned information.
            (*irp).IoStatus.Information = size_of::<CallbackInfoInput>() as u64;
            Ok(status)
        }
    }));

    // List Callbacks Removed.
    ioctls.register_handler(ENUMERATE_REMOVED_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        unsafe {
            let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
            let callback_info = get_output_buffer::<CallbackInfoOutput>(irp)?;
            let callbacks = match (*target_callback).callback {
                Callbacks::PsSetCreateProcessNotifyRoutine 
                | Callbacks::PsSetCreateThreadNotifyRoutine
                | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::enumerate_removed()?,
                
                Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::enumerate_removed()?,
                
                Callbacks::ObProcess
                | Callbacks::ObThread => shadowx::CallbackOb::enumerate_removed()?,
            };

            for (index, callback) in callbacks.iter().enumerate() {
                let info_ptr = callback_info.add(index);
                
                core::ptr::copy_nonoverlapping(callback.name.as_ptr(), (*info_ptr).name.as_mut_ptr(), callback.name.len());
                (*info_ptr).address = callback.address;
                (*info_ptr).index = callback.index as u8;
                (*info_ptr).pre_operation = callback.pre_operation;
                (*info_ptr).post_operation = callback.post_operation;
            }
        
            // Set the size of the returned information.
            (*irp).IoStatus.Information = (callbacks.len() * size_of::<CallbackInfoOutput>()) as u64;
            Ok(STATUS_SUCCESS)
        }
    }));
}
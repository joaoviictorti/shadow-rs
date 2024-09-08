use {
    alloc::vec::Vec,
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
            CallbackList, INFO_CALLBACK_RESTAURE_OB
        }, 
        includes::structs::{CallbackRestaureOb, OBCALLBACK_ENTRY}, utils::return_module
    },
};

/// Structure representing the Callback Object.
pub struct CallbackOb;

/// Implement a feature for the callback ObRegisterCallbacks (PsProcessType / PsThreadType).
impl CallbackList for CallbackOb {
    unsafe fn restore_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let mut callback_info = INFO_CALLBACK_RESTAURE_OB.lock();
        let callback_type = (*target_callback).callback;
        let index = (*target_callback).index;

        if let Some(index) = callback_info.iter().position(|c| c.callback == callback_type && c.index == index) {
            let object_type = match find_callback_address(&(*target_callback).callback) {
                Some(CallbackResult::ObRegister(addr)) => addr,
                _ => return STATUS_UNSUCCESSFUL,
            };

            let lock = &(*object_type).type_lock as *const _ as *mut u64;
            ExAcquirePushLockExclusiveEx(lock, 0);

            let current = &mut ((*object_type).callback_list) as *mut _ as *mut OBCALLBACK_ENTRY;
            let mut next = (*current).callback_list.Flink as *mut OBCALLBACK_ENTRY;

            while next != current {
                if !(*next).enabled && !next.is_null() && (*next).entry as u64 == callback_info[index].entry {
                    (*next).enabled = true;
                    callback_info.remove(index);
                    ExReleasePushLockExclusiveEx(lock, 0);
                    return STATUS_SUCCESS;
                }

                next = (*next).callback_list.Flink as *mut OBCALLBACK_ENTRY;
            }

            ExReleasePushLockExclusiveEx(lock, 0);
        } else {
            log::error!("Callback not found for type {:?} at index {}", callback_type, index);
            return STATUS_UNSUCCESSFUL;
        }

        STATUS_UNSUCCESSFUL
    }

    unsafe fn remove_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let object_type = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::ObRegister(addr)) => addr,
            _ => return STATUS_UNSUCCESSFUL,
        };

        let lock = &(*object_type).type_lock as *const _ as *mut u64;
        ExAcquirePushLockExclusiveEx(lock, 0);

        let mut i = 0;
        let index = (*target_callback).index;
        let current = &mut ((*object_type).callback_list) as *mut _ as *mut OBCALLBACK_ENTRY;
        let mut next = (*current).callback_list.Flink as *mut OBCALLBACK_ENTRY;
        let mut callback_info = INFO_CALLBACK_RESTAURE_OB.lock();

        while next != current {
            if i == index {
                if (*next).enabled {
                    let mut callback_restaure = CallbackRestaureOb {
                        index,
                        callback: (*target_callback).callback,
                        entry: (*next).entry as u64,
                        pre_operation: 0,
                        post_operation: 0
                    };

                    if let Some(pre_op) = (*next).pre_operation {
                        callback_restaure.pre_operation = pre_op as _;
                    }

                    if let Some(post_op) = (*next).post_operation {
                        callback_restaure.post_operation = post_op as _;
                    }

                    (*next).enabled = false;
    
                    callback_info.push(callback_restaure);
                    log::info!("Callback removed at index {}", index);
                }

                ExReleasePushLockExclusiveEx(lock, 0);

                return STATUS_SUCCESS;
            }

            next = (*next).callback_list.Flink as *mut OBCALLBACK_ENTRY;
            i += 1;
        }

        ExReleasePushLockExclusiveEx(lock, 0);

        STATUS_UNSUCCESSFUL
    }

    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> Result<(), NTSTATUS> {
        let object_type = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::ObRegister(addr)) => addr,
            _ => return Err(STATUS_UNSUCCESSFUL),
        };

        let current = &mut ((*object_type).callback_list) as *mut _ as *mut OBCALLBACK_ENTRY;
        let mut next = (*current).callback_list.Flink as *mut OBCALLBACK_ENTRY;
        let mut list_objects = Vec::new();
        
        while next != current {
            let mut addrs = (0, 0);
            if let Some(pre_op) = (*next).pre_operation {
                addrs.0 = pre_op as u64;
            }

            if let Some(post_op) = (*next).post_operation {
                addrs.1 = post_op as u64;
            }

            list_objects.push(((*next).enabled, addrs));

            next = (*next).callback_list.Flink as *mut OBCALLBACK_ENTRY;
        }

        let (mut ldr_data, module_count) = return_module().ok_or(STATUS_UNSUCCESSFUL)?;
        let start_entry = ldr_data;
        let mut current_index = 0;

        for (i, (enabled, addrs)) in list_objects.iter().enumerate() {
            if !enabled {
                current_index += 1;
                continue;
            }

            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;
                let pre = addrs.0;
                let post = addrs.1;

                if pre > start_address as u64 && pre < end_address || 
                    post > start_address as u64 && post < end_address
                {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );    

                    // Module name
                    let name = &mut (*callback_info.offset(i as isize)).name[..buffer.len()];
                    core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
                    // Module address
                    (*callback_info.offset(i as isize)).pre_operation = pre as usize;
                    (*callback_info.offset(i as isize)).post_operation = post as usize;

                    // Module index
                    (*callback_info.offset(i as isize)).index = current_index as u8;
            
                    *information += size_of::<CallbackInfoOutput>();
                    current_index += 1;
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
        let callback_restaure = INFO_CALLBACK_RESTAURE_OB.lock();

        let (mut ldr_data, module_count) = return_module().ok_or(STATUS_UNSUCCESSFUL)?;
        let start_entry = ldr_data;

        for (i, callback) in callback_restaure.iter().enumerate() {
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;

                if callback.pre_operation > start_address as u64 && callback.pre_operation < end_address 
                    || callback.post_operation > start_address as u64 && callback.post_operation < end_address 
                {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );
                    
                    // Module name
                    let name = &mut (*callback_info.offset(i as isize)).name[..buffer.len()];
                    core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
                    // Module address
                    (*callback_info.offset(i as isize)).pre_operation = callback.pre_operation as usize;
                    (*callback_info.offset(i as isize)).post_operation = callback.post_operation as usize;
        
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
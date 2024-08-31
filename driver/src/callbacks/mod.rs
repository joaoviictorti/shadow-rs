use {
    crate::{
        includes::structs::{CallbackRestaure, CallbackRestaureOb, CM_CALLBACK, OBCALLBACK_ENTRY}, 
        utils::return_module
    }, 
    alloc::vec::Vec,
    core::mem::size_of, 
    find_callback::{find_callback_address, CallbackResult}, 
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY, 
    shared::structs::{CallbackInfoInput, CallbackInfoOutput}, 
    spin::{lazy::Lazy, Mutex}, 
    wdk_sys::{
        ntddk::{ExAcquirePushLockExclusiveEx, ExReleasePushLockExclusiveEx}, 
        NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL
    }
};

mod find_callback;
pub mod ioctls;

/// Variable that stores callbacks that have been removed.
static mut INFO_CALLBACK_RESTAURE: Lazy<Mutex<Vec<CallbackRestaure>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(40)));

/// Variable that stores callbacks registry that have been removed.
static mut INFO_CALLBACK_RESTAURE_REGISTRY: Lazy<Mutex<Vec<CallbackRestaure>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(40)));

/// Variable that stores callbacks Ob that have been removed.
static mut INFO_CALLBACK_RESTAURE_OB: Lazy<Mutex<Vec<CallbackRestaureOb>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(40)));

/// Trait defining common operations for callback lists.
pub trait CallbackList {
    /// Restore a callback from the specified routine.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn restore_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS;

    /// Removes a callback from the specified routine.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn remove_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS;

    /// Searches for a module associated with a callback and updates callback information.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// - `callback_info`: Pointer to the callback information output.
    /// - `information`: Pointer to a variable to store information size.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS;

    /// List of callbacks currently removed.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// - `callback_info`: Pointer to the callback information output.
    /// - `information`: Pointer to a variable to store information size.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn enumerate_removed_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS;
}

/// Structure representing the Callback.
pub struct Callback;

/// Implement a feature for the callback PsSetCreateProcessNotifyRoutine / PsSetCreateThreadNotifyRoutine / PsSetLoadImageNotifyRoutine.
impl CallbackList for Callback {
    unsafe fn restore_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let mut callback_info = INFO_CALLBACK_RESTAURE.lock();
        let callback_type = (*target_callback).callback;
        let index = (*target_callback).index;

        if let Some(index) = callback_info.iter().position(|c| c.callback == callback_type && c.index == index) {
            let address = match find_callback_address(&(*target_callback).callback) {
                Some(CallbackResult::PsCreate(addr)) => addr,
                _ => return STATUS_UNSUCCESSFUL,
            };

            let addr = address.offset((callback_info[index].index * 8) as isize);
            *(addr as *mut u64) = callback_info[index].address;
            callback_info.remove(index);
        } else {
            log::error!("Callback not found for type {:?} at index {}", callback_type, index);
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
        let callback_restaure = CallbackRestaure {
            index: (*target_callback).index,
            callback: (*target_callback).callback,
            address: *(addr as *mut u64),
            ..Default::default()
        };

        let mut callback_info = INFO_CALLBACK_RESTAURE.lock();
        callback_info.push(callback_restaure);

        *(addr as *mut u64) = 0;

        log::info!("Callback removed at index {}", index);

        STATUS_SUCCESS
    }

    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS {
        let address = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::PsCreate(addr)) => addr,
            _ => return STATUS_UNSUCCESSFUL,
        };

        let (mut ldr_data, module_count) = match return_module() {
            Some(result) => result,
            None => return STATUS_UNSUCCESSFUL
        };

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

        STATUS_SUCCESS
    }
    
    unsafe fn enumerate_removed_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS {
        let callback_restaure = INFO_CALLBACK_RESTAURE.lock();

        let (mut ldr_data, module_count) = match return_module() {
            Some(result) => result,
            None => return STATUS_UNSUCCESSFUL
        };

        let start_entry = ldr_data;

        for (i, callback) in callback_restaure.iter().enumerate() {
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

        STATUS_SUCCESS
    }
}

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

    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS {
        let (callback_list_header, callback_count, callback_list_lock) = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::Registry(addr)) => addr,
            _ => return STATUS_UNSUCCESSFUL,
        };

        let count = *(callback_count as *mut u32) + 1;
        let mut pcm_callback = callback_list_header as *mut CM_CALLBACK;
        let (mut ldr_data, module_count) = match return_module() {
            Some(result) => result,
            None => return STATUS_UNSUCCESSFUL
        };
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

        STATUS_SUCCESS
    }
    
    unsafe fn enumerate_removed_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS {
        let callback_restaure = INFO_CALLBACK_RESTAURE_REGISTRY.lock();

        let (mut ldr_data, module_count) = match return_module() {
            Some(result) => result,
            None => return STATUS_UNSUCCESSFUL
        };

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

        STATUS_SUCCESS
    }
}

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

    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS {
        let object_type = match find_callback_address(&(*target_callback).callback) {
            Some(CallbackResult::ObRegister(addr)) => addr,
            _ => return STATUS_UNSUCCESSFUL,
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

        let (mut ldr_data, module_count) = match return_module() {
            Some(result) => result,
            None => return STATUS_UNSUCCESSFUL
        };

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

        STATUS_SUCCESS
    }
    
    unsafe fn enumerate_removed_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS {
        let callback_restaure = INFO_CALLBACK_RESTAURE_OB.lock();

        let (mut ldr_data, module_count) = match return_module() {
            Some(result) => result,
            None => return STATUS_UNSUCCESSFUL
        };

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

        STATUS_SUCCESS
    }
}
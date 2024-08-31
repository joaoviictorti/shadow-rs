extern crate alloc;

use {
    crate::{includes::{PsGetProcessPeb, MmCopyVirtualMemory}, process::Process}, 
    ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB}, 
    shared::structs::{ModuleInfo, TargetProcess}, 
    wdk_sys::{
        ntddk::{
            ExAllocatePool2, ExFreePool, IoGetCurrentProcess, KeStackAttachProcess, 
            KeUnstackDetachProcess,
        }, 
        KAPC_STATE, NTSTATUS, STATUS_INVALID_PARAMETER, 
        STATUS_SUCCESS, STATUS_UNSUCCESSFUL, _MODE::KernelMode, POOL_FLAG_NON_PAGED
    }, 
    winapi::shared::ntdef::LIST_ENTRY
};

pub mod ioctls;

/// Represents a module in the operating system.
pub struct Module;

impl Module {
    /// Enumerates modules in a given target process.
    /// 
    /// # Parameters
    /// - `process`: A pointer to the target process (`*mut TargetProcess`) to enumerate modules from.
    /// - `module_info`: A pointer to a `ModuleInfo` structure that will be populated with information about the modules.
    /// - `information`: A mutable reference to a `usize` that will store additional information about the module enumeration.
    ///
    /// # Returns
    /// - `NTSTATUS`: Returns `STATUS_SUCCESS` if the module enumeration is successful, otherwise returns an appropriate error status.
    ///
    pub unsafe fn enumerate_module(process: *mut TargetProcess, module_info: *mut ModuleInfo, information: &mut usize) -> NTSTATUS {
        log::info!("Starting module enumeration");

        let pid = (*process).pid;
        let mut apc_state: KAPC_STATE = core::mem::zeroed();
        let temp_info_size =  256 * core::mem::size_of::<ModuleInfo>();
        let temp_info = ExAllocatePool2(POOL_FLAG_NON_PAGED, temp_info_size as u64, u32::from_be_bytes(*b"btrd")) as *mut ModuleInfo;

        if temp_info.is_null() {
            log::error!("ExAllocatePool2 Failed to Allocate Memory");
            return STATUS_UNSUCCESSFUL
        }

        let target = match Process::new(pid) {
            Some(p) => p,
            None => return STATUS_UNSUCCESSFUL,
        };

        KeStackAttachProcess(target.e_process, &mut apc_state);
        
        let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
        if target_peb.is_null() || (*target_peb).Ldr.is_null() {
            KeUnstackDetachProcess(&mut apc_state);
            ExFreePool(temp_info as _);
            return STATUS_INVALID_PARAMETER;
        }

        let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
        let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;
        let mut count = 0;         

        while next != current  {
            if next.is_null() {
                log::error!("Next LIST_ENTRY is null");
                KeUnstackDetachProcess(&mut apc_state);
                ExFreePool(temp_info as _);
                return STATUS_UNSUCCESSFUL;
            }

            let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
            if list_entry.is_null() {
                log::error!("LDR_DATA_TABLE_ENTRY is null");
                KeUnstackDetachProcess(&mut apc_state);
                ExFreePool(temp_info as _);
                return STATUS_UNSUCCESSFUL;
            }

            let buffer = core::slice::from_raw_parts(
                (*list_entry).FullDllName.Buffer,
                ((*list_entry).FullDllName.Length / 2) as usize,
            );
            if buffer.is_empty() {
                log::error!("Buffer for module name is empty");
                KeUnstackDetachProcess(&mut apc_state);
                ExFreePool(temp_info as _);
                return STATUS_UNSUCCESSFUL;
            }

            // Module name
            let name = &mut (*temp_info.offset(count)).name.as_mut();
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            
            // Module address
            (*temp_info.offset(count)).address = (*list_entry).DllBase as usize;
            
            // Module index
            (*temp_info.offset(count)).index = count as u8;
            
            count += 1;
    
            next = (*next).Flink;
        }

        KeUnstackDetachProcess(&mut apc_state);
    
        let size_to_copy = count as usize * core::mem::size_of::<ModuleInfo>();
        let mut return_size = 0;
        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            temp_info as *mut _,
            IoGetCurrentProcess(),
            module_info as *mut _,
            size_to_copy as u64,
            KernelMode as i8,
            &mut return_size,
        );

        ExFreePool(temp_info as _);

        *information = count as usize * core::mem::size_of::<ModuleInfo>();

        STATUS_SUCCESS
    }
}

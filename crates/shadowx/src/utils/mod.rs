use {
    wdk_sys::{*, ntddk::*},
    alloc::string::{ToString, String},
    core::{
        ffi::{c_void, CStr}, 
        slice::from_raw_parts,
        ptr::{null_mut, read_unaligned}, 
    },
    ntapi::{
        ntpebteb::PEB,
        ntldr::LDR_DATA_TABLE_ENTRY,
        ntzwapi::ZwQuerySystemInformation,
        ntexapi::{
            SystemProcessInformation, 
            PSYSTEM_PROCESS_INFORMATION
        }, 
    },
    winapi::um::winnt::{
        IMAGE_DOS_HEADER, 
        IMAGE_NT_HEADERS64,
        IMAGE_EXPORT_DIRECTORY, 
    }
};

use crate::{
    *, 
    pool::PoolMemory, 
    error::ShadowError,
    process_attach::ProcessAttach
};

pub mod uni;
pub mod lock;
pub mod patterns;
pub mod address;
pub mod pool;
pub mod handle;
pub mod file;
pub mod process_attach;

/// Find a thread with an alertable status for the given process (PID).
///
/// This function queries the system for all threads associated with the specified process.
/// It checks whether each thread meets specific conditions (e.g., non-terminating and alertable)
/// and returns the `KTHREAD` pointer if such a thread is found.
///
/// # Arguments
///
/// * `target_pid` - The process identifier (PID) for which to find an alertable thread.
///
/// # Returns
///
/// * `Ok(*mut _KTHREAD)` - A pointer to the `KTHREAD` of the found alertable thread.
/// * `Err(ShadowError)` - If no suitable thread is found or an error occurs during the search.
pub unsafe fn find_thread_alertable(target_pid: usize) -> Result<*mut _KTHREAD, ShadowError> {
    // Initial call to get the necessary buffer size for system process information
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);
    
    // Allocate memory to store process information
    let info_process = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, u32::from_be_bytes(*b"oied"))
        .map(|mem| mem.ptr as PSYSTEM_PROCESS_INFORMATION)
        .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

    // Query system information to get process and thread data
    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        info_process as *mut winapi::ctypes::c_void,
        return_bytes,
        &mut return_bytes,
    );

    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed("ZwQuerySystemInformation", status));
    }

    // Iterate over process information to find the target PID and alertable thread
    let mut process_info = info_process;
    while (*process_info).NextEntryOffset != 0 {
        let pid = (*process_info).UniqueProcessId as usize;
        if pid == target_pid {
            let threads_slice = from_raw_parts((*process_info).Threads.as_ptr(), (*process_info).NumberOfThreads as usize,);
            for &thread in threads_slice {
                let thread_id = thread.ClientId.UniqueThread as usize;
                let target_thread = if let Ok(thread) = Thread::new(thread_id) { thread } else { continue };

                if PsIsThreadTerminating(target_thread.e_thread) == 1 {
                    continue;
                }

                let is_alertable = read_unaligned(target_thread.e_thread.cast::<u8>().offset(0x74) as *const u64) & 0x10;
                let is_gui_thread = read_unaligned(target_thread.e_thread.cast::<u8>().offset(0x78) as *const u64) & 0x80;
                let thread_kernel_stack = read_unaligned(target_thread.e_thread.cast::<u8>().offset(0x58) as *const u64);
                let thread_context_stack = read_unaligned(target_thread.e_thread.cast::<u8>().offset(0x268) as *const u64);

                if is_alertable == 0 && is_gui_thread != 0 && thread_kernel_stack == 0 && thread_context_stack == 0 {
                    continue;
                }

                return Ok(target_thread.e_thread)
            }
        }
        
        if (*process_info).NextEntryOffset == 0 {
            break;
        }

        process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
    }

    Err(ShadowError::FunctionExecutionFailed("find_thread_alertable", line!()))
}

/// Retrieves the address of a function within a specific module loaded in a process's PEB.
///
/// This function locates the specified module (DLL) in the process's PEB and searches for
/// the requested function within the module's export table. It returns the address of the
/// function if found.
///
/// # Arguments
///
/// * `pid` - The process identifier (PID) of the target process.
/// * `module_name` - The name of the module (e.g., DLL) to search for.
/// * `function_name` - The name of the function to locate within the module.
///
/// # Returns
///
/// * `Ok(*mut c_void)` - A pointer to the function's address if found.
/// * `Err(ShadowError)` - If the function or module is not found, or an error occurs during execution.
pub unsafe fn get_module_peb(pid: usize, module_name: &str, function_name: &str) -> Result<*mut c_void, ShadowError> {
    // Attach to the target process and access its PEB
    let target = Process::new(pid)?;
    ProcessAttach::new(target.e_process);
    let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
    if target_peb.is_null() || (*target_peb).Ldr.is_null() {
        return Err(ShadowError::FunctionExecutionFailed("PsGetProcessPeb", line!()));
    }
    
    // Traverse the InLoadOrderModuleList to find the module
    let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut winapi::shared::ntdef::LIST_ENTRY;
    let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;      

    while next != current {
        if next.is_null() {
            return Err(ShadowError::NullPointer("next LIST_ENTRY"));
        }

        let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
        if list_entry.is_null() {
            return Err(ShadowError::NullPointer("next LDR_DATA_TABLE_ENTRY"));
        }

        let buffer = core::slice::from_raw_parts(
            (*list_entry).FullDllName.Buffer,
            ((*list_entry).FullDllName.Length / 2) as usize,
        );
        if buffer.is_empty() {
            return Err(ShadowError::StringConversionFailed((*list_entry).FullDllName.Buffer as usize));
        }

        // Check if the module name matches
        let dll_name = alloc::string::String::from_utf16_lossy(buffer);
        if dll_name.to_lowercase().contains(module_name) {
            let dll_base = (*list_entry).DllBase as usize;
            let dos_header = dll_base as *mut IMAGE_DOS_HEADER;
            let nt_header = (dll_base + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
        
            let export_directory = (dll_base + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;
            let names = from_raw_parts((dll_base + (*export_directory).AddressOfNames as usize) as *const u32,(*export_directory).NumberOfNames as _);
            let functions = from_raw_parts((dll_base + (*export_directory).AddressOfFunctions as usize) as *const u32,(*export_directory).NumberOfFunctions as _);
            let ordinals = from_raw_parts((dll_base + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);
        
            // Search for the function by name in the export table
            for i in 0..(*export_directory).NumberOfNames as isize {
                let name_module = CStr::from_ptr((dll_base + names[i as usize] as usize) as *const i8)
                    .to_str()
                    .map_err(|_| ShadowError::StringConversionFailed(names[i as usize] as usize))?;

                let ordinal = ordinals[i as usize] as usize;
                let address = (dll_base + functions[ordinal] as usize) as *mut c_void;
                if name_module == function_name {
                    return Ok(address);
                }
            }
        }

        next = (*next).Flink;
    }

    Err(ShadowError::ModuleNotFound(module_name.to_string()))
}


/// Retrieves the PID of a process by its name.
///
/// # Arguments
/// 
/// * `process_name` - A string slice containing the name of the process.
///
/// # Returns
/// 
/// * `Option<usize>` - An optional containing the PID of the process, or None if the process is not found.
pub unsafe fn get_process_by_name(process_name: &str) -> Result<usize, ShadowError> {
    
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);
    
    let info_process = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, u32::from_be_bytes(*b"diws"))
        .map(|mem| mem.ptr as PSYSTEM_PROCESS_INFORMATION)
        .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        info_process as *mut winapi::ctypes::c_void,
        return_bytes,
        &mut return_bytes,
    );
    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed("ZwQuerySystemInformation", status));
    }

    let mut process_info = info_process;

    loop {
        if !(*process_info).ImageName.Buffer.is_null() {
            let image_name = from_raw_parts((*process_info).ImageName.Buffer, ((*process_info).ImageName.Length / 2) as usize);
            let name = String::from_utf16_lossy(image_name);
            if name == process_name {
                let pid = (*process_info).UniqueProcessId as usize;
                return Ok(pid);
            }
        }

        if (*process_info).NextEntryOffset == 0 {
            break;
        }

        process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
    }

    Err(ShadowError::ProcessNotFound(process_name.to_string()))
}


/// Validates if the given address is within the kernel memory range.
///
/// # Arguments
///
/// * `addr` - A 64-bit unsigned integer representing the address to validate.
///
/// # Returns
/// 
/// * `bool` - True if the address is within the kernel memory range, False otherwise.
pub fn valid_kernel_memory(addr: u64) -> bool {
    addr > 0x8000000000000000 && addr < 0xFFFFFFFFFFFFFFFF
}

/// Validates if the given address is within the user memory range.
///
/// # Arguments
/// 
/// * `addr` - A 64-bit unsigned integer representing the address to validate.
///
/// # Returns
///
/// * `bool` - True if the address is within the user memory range, False otherwise.
pub fn valid_user_memory(addr: u64) -> bool {
    addr > 0 && addr < 0x7FFFFFFFFFFFFFFF
}

/// Responsible for returning information on the modules loaded.
///
/// # Returns
///
/// - `Option<(*mut LDR_DATA_TABLE_ENTRY, i32)> `: Returns a content containing LDR_DATA_TABLE_ENTRY and the return of how many loaded modules there are in PsLoadedModuleList.
/// 
pub fn list_modules() -> Result<(*mut LDR_DATA_TABLE_ENTRY, i32), ShadowError> {
    let ps_module = crate::uni::str_to_unicode(obfstr::obfstr!("PsLoadedModuleList"));
    let func = unsafe { MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY };

    if func.is_null() {
        return Err(ShadowError::NullPointer("LDR_DATA_TABLE_ENTRY"))
    }

    let mut list_entry = unsafe { (*func).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY };
    let mut module_count = 0;

    let start_entry = list_entry;
    while !list_entry.is_null() && list_entry != func {
        module_count += 1;
        list_entry = unsafe { (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY };
    }

    Ok((start_entry, module_count))
}

/// Initializes the `OBJECT_ATTRIBUTES` structure.
///
/// # Arguments
///
/// * `object_name` - An optional pointer to a `UNICODE_STRING` representing the name of the object. 
///   If `None`, the object name is set to `null_mut()`.
/// * `attributes` - A `u32` representing the attributes of the object (e.g., `OBJ_CASE_INSENSITIVE`, `OBJ_KERNEL_HANDLE`).
/// * `root_directory` - An optional pointer to a root directory. If the object resides in a directory, 
///   this pointer represents the root directory. If `None`, it is set to `null_mut()`.
/// * `security_descriptor` - An optional pointer to a security descriptor that defines 
///   access control. If `None`, it is set to `null_mut()`.
/// * `security_quality_of_service` - An optional pointer to a security quality of service structure. 
///   If `None`, it is set to `null_mut()`.
///
/// # Returns
///
/// * Returns an `OBJECT_ATTRIBUTES` structure initialized with the provided parameters. 
/// If optional arguments are not provided, their corresponding fields are set to `null_mut()`.
#[allow(non_snake_case)]
pub fn InitializeObjectAttributes(
    object_name: Option<*mut UNICODE_STRING>,
    attributes: u32,
    root_directory: Option<*mut c_void>,
    security_descriptor: Option<*mut c_void>,
    security_quality_of_service: Option<*mut c_void>
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_directory.unwrap_or(null_mut()),
        ObjectName: object_name.unwrap_or(null_mut()),
        Attributes: attributes,
        SecurityDescriptor: security_descriptor.unwrap_or(null_mut()),
        SecurityQualityOfService: security_quality_of_service.unwrap_or(null_mut())
    }
}
use alloc::string::{String, ToString};
use core::{
    ffi::{c_void, CStr},
    ptr::null_mut,
    slice::from_raw_parts,
};

use wdk_sys::{
    *, 
    _KWAIT_REASON::{
        WrAlertByThreadId, 
        DelayExecution, 
        UserRequest
    },
    ntddk::{
        MmGetSystemRoutineAddress, 
        PsIsThreadTerminating
    },
};

use ntapi::ntexapi::{
    SystemProcessInformation, 
    PSYSTEM_PROCESS_INFORMATION
};

use crate::data::{
    KTHREAD_STATE::Waiting, 
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, 
    IMAGE_NT_HEADERS, PEB, LDR_DATA_TABLE_ENTRY
};

use crate::{
    *, 
    error::ShadowError, 
    pool::PoolMemory,
    attach::ProcessAttach,
    ZwQuerySystemInformation,
};

pub mod address;
pub mod attach;
pub mod file;
pub mod handle;
pub mod lock;
pub mod patterns;
pub mod pool;
pub mod uni;
pub mod mdl;

/// Find a thread with an alertable status for the given process (PID).
///
/// # Arguments
///
/// * `target_pid` - The process identifier (PID) for which to find an alertable thread.
///
/// # Returns
///
/// * `Ok(*mut _KTHREAD)` - A pointer to the `KTHREAD` of the found alertable thread.
/// * `Err(ShadowError)` - If no suitable thread is found or an error occurs during the search.
pub unsafe fn find_thread_alertable(target_pid: usize) -> Result<*mut _KTHREAD> {
    // Initial call to get the necessary buffer size for system process information
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);

    // Allocate memory to store process information
    let info_process = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, "oied")
        .map(|mem| mem.ptr as PSYSTEM_PROCESS_INFORMATION)
        .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

    // Query system information to get process and thread data
    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        info_process as *mut c_void,
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
            let threads_slice = from_raw_parts((*process_info).Threads.as_ptr(), (*process_info).NumberOfThreads as usize);
            for &thread in threads_slice {
                if thread.ThreadState == Waiting as u32 && 
                    thread.WaitReason == WrAlertByThreadId as u32 || 
                    thread.WaitReason == UserRequest as u32 ||
                    thread.WaitReason == DelayExecution as u32
                {
                    let target_thread = if let Ok(thread) = Thread::new(thread.ClientId.UniqueThread as usize) {
                        thread
                    } else {
                        continue;
                    };
    
                    if PsIsThreadTerminating(target_thread.e_thread) == 1 {
                        continue;
                    }

                    return Ok(target_thread.e_thread);
                }
            }
        }

        if (*process_info).NextEntryOffset == 0 {
            break;
        }

        process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
    }

    Err(ShadowError::FunctionExecutionFailed("find_thread_alertable", line!()))
}

///
///
///
pub unsafe fn find_thread(target_pid: usize) -> Result<*mut _KTHREAD> {
    // Initial call to get the necessary buffer size for system process information
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);

    // Allocate memory to store process information
    let info_process = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, "oied")
        .map(|mem| mem.ptr as PSYSTEM_PROCESS_INFORMATION)
        .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

    // Query system information to get process and thread data
    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        info_process as *mut c_void,
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
            let threads_slice = from_raw_parts((*process_info).Threads.as_ptr(), (*process_info).NumberOfThreads as usize);
            for &thread in threads_slice {
                let thread_id = thread.ClientId.UniqueThread as usize;
                let target_thread = if let Ok(thread) = Thread::new(thread_id) {
                    thread
                } else {
                    continue;
                };

                if PsIsThreadTerminating(target_thread.e_thread) == 1 {
                    continue;
                }

                return Ok(target_thread.e_thread);
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
pub unsafe fn get_function_peb(pid: usize, module_name: &str, function_name: &str) -> Result<*mut c_void> {
    // Recovering `PEPROCESS`
    let process = Process::new(pid)?;
    let mut attach_process = ProcessAttach::new(process.e_process);

    // Access its `PEB`
    let peb = PsGetProcessPeb(process.e_process) as *mut PEB;
    if peb.is_null() || (*peb).Ldr.is_null() {
        return Err(ShadowError::FunctionExecutionFailed("PsGetProcessPeb", line!()));
    }

    // Traverse the InLoadOrderModuleList to find the module    
    let current = &mut (*(*peb).Ldr).InLoadOrderModuleList;
    let mut next = (*(*peb).Ldr).InLoadOrderModuleList.Flink;

    while next != current {
        if next.is_null() {
            return Err(ShadowError::NullPointer("next LIST_ENTRY"));
        }

        let ldr_data = next as *mut LDR_DATA_TABLE_ENTRY;
        if ldr_data.is_null() {
            return Err(ShadowError::NullPointer("next LDR_DATA_TABLE_ENTRY"));
        }

        let buffer = from_raw_parts(
            (*ldr_data).FullDllName.Buffer,
            ((*ldr_data).FullDllName.Length / 2) as usize,
        );

        if buffer.is_empty() {
            return Err(ShadowError::StringConversionFailed((*ldr_data).FullDllName.Buffer as usize));
        }

        // Check if the module name matches
        let dll_name = alloc::string::String::from_utf16_lossy(buffer);
        if dll_name.to_lowercase().contains(module_name) {
            let dll_base = (*ldr_data).DllBase as usize;
            let dos_header = dll_base as *mut IMAGE_DOS_HEADER;
            let nt_header = (dll_base + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS;

            // Retrieves the size of the export table
            let export_directory = (dll_base as usize + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize)
                as *const IMAGE_EXPORT_DIRECTORY;

            // Retrieving information from module names
            let names = from_raw_parts(
                (dll_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
                (*export_directory).NumberOfNames as usize,
            );

            // Retrieving information from functions
            let functions = from_raw_parts(
                (dll_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
                (*export_directory).NumberOfFunctions as usize,
            );
            
            // Retrieving information from ordinals
            let ordinals = from_raw_parts(
                (dll_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
                (*export_directory).NumberOfNames as usize,
            );

            // Search for the function by name in the export table
            for i in 0..(*export_directory).NumberOfNames as usize {
                let ordinal = ordinals[i] as usize;
                let address = (dll_base + functions[ordinal] as usize) as *mut c_void;
                let name = CStr::from_ptr((dll_base + names[i] as usize) as *const i8)
                        .to_str()
                        .map_err(|_| ShadowError::StringConversionFailed(names[i] as usize))?;
                    
                if name == function_name {
                    return Ok(address);
                }
            }
        }

        next = (*next).Flink;
    }

    // Detaches the target process
    attach_process.detach();

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
pub unsafe fn get_process_by_name(process_name: &str) -> Result<usize> {
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);

    let info_process = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, "diws")
        .map(|mem| mem.ptr as PSYSTEM_PROCESS_INFORMATION)
        .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        info_process as *mut c_void,
        return_bytes,
        &mut return_bytes,
    );

    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed("ZwQuerySystemInformation", status));
    }

    let mut process_info = info_process;
    loop {
        if !(*process_info).ImageName.Buffer.is_null() {
            let image_name = from_raw_parts(
                (*process_info).ImageName.Buffer,
                ((*process_info).ImageName.Length / 2) as usize,
            );

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
/// * True if the address is within the kernel memory range, False otherwise.
pub fn valid_kernel_memory(addr: u64) -> bool {
    (addr >> 48) == 0xFFFF
}

/// Validates if the given address is within the user memory range.
///
/// # Arguments
///
/// * `addr` - A 64-bit unsigned integer representing the address to validate.
///
/// # Returns
///
/// * True if the address is within the user memory range, False otherwise.
pub fn valid_user_memory(addr: u64) -> bool {
    (addr >> 48) == 0x0000
}

/// Responsible for returning information on the modules loaded.
///
/// # Returns
///
/// - `Option<(*mut LDR_DATA_TABLE_ENTRY, i32)> `: Returns a content containing LDR_DATA_TABLE_ENTRY
///     and the return of how many loaded modules there are in PsLoadedModuleList.
pub fn modules() -> Result<(*mut LDR_DATA_TABLE_ENTRY, i32)> {
    let ps_module = crate::uni::str_to_unicode(obfstr::obfstr!("PsLoadedModuleList"));
    let ldr_data = unsafe { MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY };
    if ldr_data.is_null() {
        return Err(ShadowError::NullPointer("LDR_DATA_TABLE_ENTRY"));
    }

    let mut list_entry = unsafe { (*ldr_data).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY };
    let mut count = 0;

    let start_entry = list_entry;
    while !list_entry.is_null() && list_entry != ldr_data {
        count += 1;
        list_entry = unsafe { (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY };
    }

    Ok((start_entry, count))
}

/// Initializes the `OBJECT_ATTRIBUTES` structure.
///
/// # Returns
///
/// * Returns an `OBJECT_ATTRIBUTES` structure initialized with the provided parameters.
pub fn InitializeObjectAttributes(
    object_name: Option<*mut UNICODE_STRING>,
    attributes: u32,
    root_directory: Option<*mut c_void>,
    security_descriptor: Option<*mut c_void>,
    security_quality_of_service: Option<*mut c_void>,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_directory.unwrap_or(null_mut()),
        ObjectName: object_name.unwrap_or(null_mut()),
        Attributes: attributes,
        SecurityDescriptor: security_descriptor.unwrap_or(null_mut()),
        SecurityQualityOfService: security_quality_of_service.unwrap_or(null_mut()),
    }
}

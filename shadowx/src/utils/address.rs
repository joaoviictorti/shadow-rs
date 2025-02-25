use core::{
    ffi::{c_void, CStr},
    ptr::null_mut,
    slice::from_raw_parts,
};

use wdk_sys::{NT_SUCCESS, POOL_FLAG_NON_PAGED};
use ntapi::ntexapi::SystemModuleInformation;
use {
    super::pool::PoolMemory, 
    alloc::string::ToString
};
use crate::data::{
    IMAGE_DOS_HEADER, 
    IMAGE_EXPORT_DIRECTORY, 
    IMAGE_NT_HEADERS,
};

use crate::{
    data::ZwQuerySystemInformation,
    error::ShadowError, Result, 
    SystemModuleInformation
};

/// Gets the base address of a specified module by querying system module information.
/// This function queries the system for all loaded modules and compares their names
/// to the provided module name to find the base address.
///
/// # Arguments
///
/// * `module_name` - A string slice containing the name of the module to locate.
///
/// # Returns
///
/// * `Ok(*mut c_void)` - A pointer to the base address of the module if found.
/// * `Err(ShadowError)` - If the module is not found or an error occurs during execution.
pub unsafe fn get_module_base_address(module_name: &str) -> Result<*mut c_void> {
    // Initial call to ZwQuerySystemInformation to get the required buffer size for system module info
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, null_mut(), 0, &mut return_bytes);

    // Allocates non-paged pool memory to store system module information
    let info_module = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, "dsdx")
        .map(|mem| mem.ptr as *mut SystemModuleInformation) // Converts to the appropriate type
        .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

    // Clears the allocated memory to ensure no garbage data is present
    core::ptr::write_bytes(info_module as *mut u8, 0, return_bytes as usize);

    // Retrieves the actual system module information
    let status = ZwQuerySystemInformation(
        SystemModuleInformation,
        info_module as *mut c_void,
        return_bytes,
        &mut return_bytes,
    );

    if !NT_SUCCESS(status) {
        return Err(ShadowError::ApiCallFailed(
            "ZwQuerySystemInformation",
            status,
        ));
    }

    // Iterates over the list of modules to find the one that matches the provided name
    let module_count = (*info_module).ModuleCount;
    for i in 0..module_count as usize {
        let name = (*info_module).Modules[i].ImageName;
        let module_base = (*info_module).Modules[i].ImageBase as *mut c_void;
        if let Ok(name_str) = core::str::from_utf8(&name) {
            if name_str.contains(module_name) {
                return Ok(module_base);
            }
        }
    }

    // If the module is not found, return an error
    Err(ShadowError::FunctionExecutionFailed("get_module_base_address", line!()))
}

/// Gets the address of a specified function within a module.
///
/// # Arguments
///
/// * `function_name` - A string slice containing the name of the function.
/// * `dll_base` - A pointer to the base address of the DLL.
///
/// # Returns
///
/// * `Some(*mut c_void)` - An pointer to the function's address.
/// * `None` if the function is not found.
pub unsafe fn get_function_address(
    function_name: &str,
    dll_base: *mut c_void,
) -> Result<*mut c_void> {
    let dos_header = dll_base as *const IMAGE_DOS_HEADER;
    let nt_header = (dll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

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

    for i in 0..(*export_directory).NumberOfNames as usize {
        let name = CStr::from_ptr((dll_base as usize + names[i] as usize) as *const i8)
            .to_str()
            .map_err(|_| ShadowError::StringConversionFailed(names[i as usize] as usize))?;

        let ordinal = ordinals[i] as usize;
        let address = (dll_base as usize + functions[ordinal] as usize) as *mut c_void;
        if name == function_name {
            return Ok(address);
        }
    }

    Err(ShadowError::FunctionNotFound(function_name.to_string()))
}

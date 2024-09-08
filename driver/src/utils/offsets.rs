use crate::utils::uni;
use wdk_sys::ntddk::MmGetSystemRoutineAddress;

/// Gets the offset of the `SignatureLevel` in the `EPROCESS` structure.
///
/// # Return
/// - `isize`: Returns the offset of the dynamically retrieved structure.
///
pub unsafe fn get_offset_signature() -> isize {
    let mut function_name = uni::str_to_unicode("PsGetProcessSignatureLevel").to_unicode();
    let address = MmGetSystemRoutineAddress(&mut function_name);
    let bytes = core::slice::from_raw_parts(address as *const u8, 20);
    let offset = bytes[15..17]
        .try_into()
        .map(u16::from_le_bytes)
        .expect("Slice length is not 2, cannot convert");

    log::info!("EPROCESS.SignatureLevel: {:#x}", offset);

    offset as isize
}

/// Gets the offset of the `UniqueProcessId` in the `EPROCESS` structure.
///
/// # Return
/// - `isize`: Returns the offset of the dynamically retrieved structure.
///
pub unsafe fn get_offset_unique_process_id() -> isize {
    let mut function_name = uni::str_to_unicode("PsGetProcessId").to_unicode();
    let address = MmGetSystemRoutineAddress(&mut function_name);
    let bytes = core::slice::from_raw_parts(address as *const u8, 5);
    let offset = bytes[3..5]
        .try_into()
        .map(u16::from_le_bytes)
        .expect("Slice length is not 2, cannot convert");

    log::info!("EPROCESS.UniqueProcessId: {:#x}", offset);

    offset as isize
}

/// Gets the offset of the `Token` in the `EPROCESS` structure.
///
/// # Return
/// - `isize`: Returns the offset of the dynamically retrieved structure.
///
pub unsafe fn get_offset_token() -> isize {
    let mut function_name = uni::str_to_unicode("PsReferencePrimaryToken").to_unicode();
    let address = MmGetSystemRoutineAddress(&mut function_name);
    let bytes = core::slice::from_raw_parts(address as *const u8, 27);
    let offset = bytes[21..23]
        .try_into()
        .map(u16::from_le_bytes)
        .expect("Slice length is not 2, cannot convert");

    log::info!("EPROCESS.Token: {:#x}", offset);

    offset as isize
}

/// Gets the offset of the `RundownProtect` in the `ETHREAD` structure.
///
/// # Return
/// - `isize`: Returns the offset of the dynamically retrieved structure.
///
pub unsafe fn get_rundown_protect() -> isize {
    let mut function_name = uni::str_to_unicode("PsGetThreadExitStatus").to_unicode();
    let address = MmGetSystemRoutineAddress(&mut function_name);
    let bytes = core::slice::from_raw_parts(address as *const u8, 17);
    let offset = bytes[13..15]
        .try_into()
        .map(u16::from_le_bytes)
        .expect("Slice length is not 2, cannot convert");

    log::info!("ETHREAD.RundownProtect: {:#x}", offset);

    offset as isize
}

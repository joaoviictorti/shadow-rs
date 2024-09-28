use crate::utils::uni;
use wdk_sys::ntddk::MmGetSystemRoutineAddress;

pub static mut BUILD_NUMBER: u32 = 0;
const WIN_1507: u32 = 10240;
const WIN_1511: u32 = 10586;
const WIN_1607: u32 = 14393;
const WIN_1703: u32 = 15063;
const WIN_1709: u32 = 16299;
const WIN_1803: u32 = 17134;
const WIN_1809: u32 = 17763;
const WIN_1903: u32 = 18362;
const WIN_1909: u32 = 18363;
#[allow(dead_code)]
const WIN_2004: u32 = 19041;
#[allow(dead_code)]
const WIN_20H2: u32 = 19042;
#[allow(dead_code)]
const WIN_21H1: u32 = 19043;
#[allow(dead_code)]
const WIN_21H2: u32 = 19044;
#[allow(dead_code)]
const WIN_22H2: u32 = 19045;
#[allow(dead_code)]
const WIN_1121H2: u32 = 22000;
#[allow(dead_code)]
const WIN_1122H2: u32 = 22621;

/// Gets the offset of the `SignatureLevel` in the `EPROCESS` structure.
///
/// # Returns
/// 
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
    
    offset as isize
}

/// Gets the offset of the `UniqueProcessId` in the `EPROCESS` structure.
///
/// # Returns
/// 
/// - `isize`: Returns the offset of the dynamically retrieved structure.
///
/// 
pub unsafe fn get_offset_unique_process_id() -> isize {
    let mut function_name = uni::str_to_unicode("PsGetProcessId").to_unicode();
    let address = MmGetSystemRoutineAddress(&mut function_name);
    let bytes = core::slice::from_raw_parts(address as *const u8, 5);
    let offset = bytes[3..5]
        .try_into()
        .map(u16::from_le_bytes)
        .expect("Slice length is not 2, cannot convert");

    offset as isize
}

/// Gets the offset of the `Token` in the `EPROCESS` structure.
///
/// # Returns
/// 
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

    offset as isize
}

/// Gets the offset of the `RundownProtect` in the `ETHREAD` structure.
///
/// # Returns
/// 
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

    offset as isize
}

/// Returns the virtual address descriptor (VAD) root offset based on the Windows build number.
///
/// # Returns
///
/// - `u32`: value representing the offset for the VAD root depending on the Windows build number.
///
#[inline]
pub unsafe fn get_vad_root() -> u32 {
    match BUILD_NUMBER {
        WIN_1507 => 0x608,
        WIN_1511 => 0x610,
        WIN_1607 => 0x620,
        WIN_1703 | WIN_1709 | WIN_1803 | WIN_1809 => 0x628,
        WIN_1903 | WIN_1909 => 0x658,
        _ => 0x7d8,
    }
}

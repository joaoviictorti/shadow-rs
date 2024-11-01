use spin::Lazy;
use wdk_sys::{ntddk::RtlGetVersion, RTL_OSVERSIONINFOW};

/// Constant values for Windows build numbers.
const WIN_1507: u32 = 10240;
const WIN_1511: u32 = 10586;
const WIN_1607: u32 = 14393;
const WIN_1703: u32 = 15063;
const WIN_1709: u32 = 16299;
const WIN_1803: u32 = 17134;
const WIN_1809: u32 = 17763;
const WIN_1903: u32 = 18362;
const WIN_1909: u32 = 18363;
const WIN_2004: u32 = 19041;
const WIN_20H2: u32 = 19042;
const WIN_21H1: u32 = 19043;
const WIN_21H2: u32 = 19044;
const WIN_22H2: u32 = 19045;

/// Constant values for Windows build numbers (Not currently used)
#[allow(dead_code)]
const WIN_1121H2: u32 = 22000;
#[allow(dead_code)]
const WIN_1122H2: u32 = 22621;

/// Holds the Windows build number initialized at runtime.
///
/// This value is fetched using the `get_windows_build_number` function,
/// which utilizes the `RtlGetVersion` API from the Windows kernel.
static BUILD_NUMBER: Lazy<u32> = Lazy::new(|| get_windows_build_number());

/// Retrieves the process lock offset based on the current Windows build number.
///
/// This function returns the offset for the process lock field in the `EPROCESS` structure
/// for the current version of Windows.
///
/// # Returns
///
/// * The offset (in bytes) to the process lock field.
#[inline]
pub fn get_process_lock() -> isize {
    match *BUILD_NUMBER {
        WIN_1507 => 0x608,
        WIN_1511 => 0x610,
        WIN_1607 => 0x620,
        WIN_1703 | WIN_1709 | WIN_1803 | WIN_1809 => 0x628,
        WIN_1903 | WIN_1909 => 0x658,
        _ => 0x7d8,
    }
}

/// Retrieves the active process link offset based on the current Windows build number.
///
/// This function returns the offset for the active process link in the `EPROCESS` structure,
/// which points to the list of processes in the active process chain.
///
/// # Returns
///
/// * The offset (in bytes) to the active process link.
#[inline]
pub fn get_active_process_link_offset() -> isize {
    match *BUILD_NUMBER {
        WIN_1507 | WIN_1511 | WIN_1607 | WIN_1903 | WIN_1909 => 0x2f0,
        WIN_1703 | WIN_1709 | WIN_1803 | WIN_1809 => 0x2e8,
        _ => 0x448
    }
}

/// Retrieves the VAD root offset based on the current Windows build number.
///
/// This function returns the offset for the VAD (Virtual Address Descriptor) root
/// in the `EPROCESS` structure for different Windows versions.
///
/// # Returns
///
/// * The offset (in bytes) to the VAD root field.
#[inline]
pub fn get_vad_root() -> u32 {
    match *BUILD_NUMBER {
        WIN_1507 => 0x608,
        WIN_1511 => 0x610,
        WIN_1607 => 0x620,
        WIN_1703 | WIN_1709 | WIN_1803 | WIN_1809 => 0x628,
        WIN_1903 | WIN_1909 => 0x658,
        _ => 0x7d8,
    }
}

/// Retrieves the token offset based on the current Windows build number.
///
/// This function returns the offset for the token field in the `EPROCESS` structure,
/// which points to the access token that represents the security context of a process.
/// The token contains privileges, group memberships, and other security-related information.
///
/// # Returns
///
/// * The offset (in bytes) to the token field in the `EPROCESS` structure.
#[inline]
pub fn get_token_offset() -> isize {
    match *BUILD_NUMBER {
        WIN_1903 | WIN_1909 => 0x360,
        WIN_1507 | WIN_1511 | WIN_1607 | WIN_1703 | WIN_1709 
            | WIN_1803 | WIN_1809 => 0x358,
        _ => 0x4b8,
    }
}

/// Retrieves the protection signature offset based on the current Windows build number.
///
/// This function returns the offset for the protection signature field in the `EPROCESS` structure.
/// This field defines the protection type and the signer of the protection for the process,
/// allowing certain processes to be protected from termination or modification.
///
/// # Returns
///
/// * The offset (in bytes) to the protection signature field in the `EPROCESS` structure.
#[inline]
pub fn get_signature_offset() -> isize {
    match *BUILD_NUMBER {
        WIN_1903 | WIN_1909 => 0x6f8,
        WIN_1703 | WIN_1709 | WIN_1803 | WIN_1809 => 0x6c8,
        WIN_1607 => 0x6c0,
        WIN_1511 => 0x6b0,
        WIN_1507 => 0x6a8,
        _ => 0x878
    }
}

/// Retrieves the thread list entry offset based on the current Windows build number.
///
/// This function returns the offset for the thread list entry in the `EPROCESS` structure.
/// The thread list entry links all the threads belonging to a process, allowing the system
/// to traverse the list of threads for each process.
///
/// # Returns
///
/// * The offset (in bytes) to the thread list entry in the `EPROCESS` structure.
#[inline] 
pub fn get_thread_lock_offset() -> isize {
    match *BUILD_NUMBER {
        WIN_1507 | WIN_1511 => 0x690,
        WIN_1607 => 0x698,
        WIN_1703 => 0x6a0,
        WIN_1709 | WIN_1803 | WIN_1809 => 0x6a8,
        WIN_1903 | WIN_1909 => 0x6b8,
        WIN_2004 | WIN_20H2 | WIN_21H1 | WIN_21H2 => 0x4e8,
        WIN_22H2 => 0x500,
        _ => 0x538
    }
}

/// Retrieves the thread lock offset based on the current Windows build number.
///
/// This function returns the offset for the thread lock field in the `EPROCESS` structure.
/// The thread lock is used to synchronize access to the list of threads within a process,
/// ensuring thread-safe operations when managing process threads.
///
/// # Returns
///
/// * The offset (in bytes) to the thread lock field in the `EPROCESS` structure.
#[inline]
pub fn get_thread_list_entry_offset() -> isize {
    match *BUILD_NUMBER {
        WIN_1507 => 0x480,
        WIN_1511 | WIN_1607 | WIN_1703 | WIN_1709 | WIN_1803 | WIN_1809
            | WIN_1903 | WIN_1909 => 0x488,
        WIN_22H2 => 0x4e8,
        _ => 0x5e0
    }
}

/// Retrieves the Windows build number using the `RtlGetVersion` API.
///
/// This function calls the `RtlGetVersion` kernel API to retrieve information about the OS version,
/// including the build number. It is used to determine which Windows version the code is running on.
///
/// # Returns
///
/// * The Windows build number or `0` if the call to `RtlGetVersion` fails.
pub fn get_windows_build_number() -> u32 {
    unsafe {
        let mut os_info: RTL_OSVERSIONINFOW = core::mem::zeroed();
        if RtlGetVersion(&mut os_info) == 0 {
            return os_info.dwBuildNumber;
        }
    }

    0
}

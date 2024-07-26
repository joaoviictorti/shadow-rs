#![allow(non_upper_case_globals)]

use {
    crate::registry::Registry,
    crate::utils::valid_kernel_memory,
    alloc::string::String, 
    core::{ffi::c_void, ptr::null_mut},
    wdk_sys::{
        *,
        ntddk::{
            CmCallbackGetKeyObjectIDEx, CmCallbackReleaseKeyObjectIDEx
        }, 
        _REG_NOTIFY_CLASS::{
            RegNtPreDeleteKey, RegNtPreDeleteValueKey, RegNtPreSetValueKey
        }
    }
};

/// Handle for Registry Callback
pub static mut CALLBACK_REGISTRY: LARGE_INTEGER = unsafe { core::mem::zeroed() };

/// The registry callback function handles registry-related operations based on the notification class.
///
/// # Parameters
/// - `_callback_context`: A pointer to the callback context, usually not used.
/// - `argument1`: A pointer to the notification class.
/// - `argument2`: A pointer to the information related to the registry operation.
///
/// # Returns
/// - `NTSTATUS`: A status code indicating the result of the operation.
/// 
pub unsafe extern "C" fn registry_callback(
    _callback_context: *mut c_void,
    argument1: *mut c_void,
    argument2: *mut c_void,
) -> NTSTATUS {
    let status;

    let reg_notify_class = argument1 as i32;
    match reg_notify_class {
        RegNtPreSetValueKey => {
            status = pre_set_value_key(argument2 as *mut REG_SET_VALUE_KEY_INFORMATION);
        },
        RegNtPreDeleteValueKey => {
            status = pre_delete_value_key(argument2 as *mut REG_DELETE_VALUE_KEY_INFORMATION);
        },
        RegNtPreDeleteKey => {
            status = pre_delete_key(argument2 as *mut REG_DELETE_KEY_INFORMATION);
        }
        _ => return STATUS_SUCCESS,
    }

    status
}   

/// Handles the pre-delete key operation.
///
/// # Parameters
/// - `info`: A pointer to `REG_DELETE_KEY_INFORMATION`.
///
/// # Returns
/// - `NTSTATUS`: A status code indicating success or failure.
/// 
unsafe fn pre_delete_key(info: *mut REG_DELETE_KEY_INFORMATION) -> NTSTATUS {
    let status;
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err
    };

    status = if Registry::check_key(key) {
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    };

    status
}

/// Handles the pre-delete value key operation.
///
/// # Parameters
/// - `info`: A pointer to `REG_DELETE_VALUE_KEY_INFORMATION`.
///
/// # Returns
/// - `NTSTATUS`: A status code indicating success or failure.
/// 
unsafe fn pre_delete_value_key(info: *mut REG_DELETE_VALUE_KEY_INFORMATION) -> NTSTATUS {
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err
    };

    let value_name = (*info).ValueName;
    if (*info).ValueName.is_null() || (*value_name).Buffer.is_null() || (*value_name).Length == 0 || !valid_kernel_memory((*value_name).Buffer as u64) {
        return STATUS_SUCCESS;
    }

    let buffer = core::slice::from_raw_parts((*value_name).Buffer, ((*value_name).Length / 2) as usize);
    let name = String::from_utf16_lossy(buffer);
    if Registry::check_target(key.clone(), name.clone()) {
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    }
}

/// Handles the pre-set value key operation.
///
/// # Parameters
/// - `info`: A pointer to `REG_SET_VALUE_KEY_INFORMATION`.
///
/// # Returns
/// - `NTSTATUS`: A status code indicating success or failure.
/// 
unsafe fn pre_set_value_key(info: *mut REG_SET_VALUE_KEY_INFORMATION) -> NTSTATUS {
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err
    };

    let value_name = (*info).ValueName;
    if (*info).ValueName.is_null() || (*value_name).Buffer.is_null() || (*value_name).Length == 0 || !valid_kernel_memory((*value_name).Buffer as u64) {
        return STATUS_SUCCESS;
    }

    let buffer = core::slice::from_raw_parts((*value_name).Buffer,((*value_name).Length / 2) as usize);
    let name = String::from_utf16_lossy(buffer);
    if Registry::check_target(key.clone(), name.clone()) {
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    }
}

/// Reads the key name from the registry information.
///
/// # Parameters
/// - `info`: A pointer to the registry information.
///
/// # Returns
/// - `Result<String, NTSTATUS>`: The key name or an error status.
/// 
unsafe fn read_key<T: RegistryInfo>(info: *mut T) -> Result<String, NTSTATUS> {
    let mut reg_path: PCUNICODE_STRING = core::ptr::null_mut();
    let status = CmCallbackGetKeyObjectIDEx(
        core::ptr::addr_of_mut!(CALLBACK_REGISTRY), 
        (*info).get_object(), 
        null_mut(), 
        &mut reg_path, 
        0
    );

    if !NT_SUCCESS(status) {
        return Err(STATUS_SUCCESS)
    }

    if reg_path.is_null() || (*reg_path).Buffer.is_null() || (*reg_path).Length == 0 || !valid_kernel_memory((*reg_path).Buffer as u64) {
        CmCallbackReleaseKeyObjectIDEx(reg_path);
        return Err(STATUS_SUCCESS);
    } 

    let buffer = core::slice::from_raw_parts((*reg_path).Buffer, ((*reg_path).Length / 2) as usize);
    let name = String::from_utf16_lossy(buffer);

    CmCallbackReleaseKeyObjectIDEx(reg_path);

    Ok(name)
}

/// Trait for accessing the object in registry information.
trait RegistryInfo {
    fn get_object(&self) -> *mut c_void;
}

impl RegistryInfo for REG_DELETE_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

impl RegistryInfo for REG_DELETE_VALUE_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

impl RegistryInfo for REG_SET_VALUE_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

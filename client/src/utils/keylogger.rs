use super::VK_CHARS;
use crate::{
    is_key_down, 
    set_key_down,
    modules::{
        KEY_PREVIOUS, 
        KEY_RECENT, 
        KEY_STATE
    },
};

/// Updates the status of the keys.
pub fn update_key_state() {
    unsafe {
        for i in 0..256 {
            if is_key_down!(KEY_STATE, i) && !(is_key_down!(KEY_PREVIOUS, i)) {
                set_key_down!(KEY_RECENT, i, true);
            }
        }
    }
}

/// Checks if a key has been pressed.
///
/// # Arguments
///
/// * `key` - The key code.
///
/// # Returns
///
/// * `bool` - if the key was pressed, otherwise `false`.
pub fn key_pressed(key: u8) -> bool {
    unsafe {
        let result = is_key_down!(KEY_RECENT, key);
        set_key_down!(KEY_RECENT, key, false);
        result
    }
}

/// Converts a virtual key code to a character.
///
/// # Arguments
///
/// * `key` - The code for the virtual key.
///
/// # Returns
///
/// * A string representing the character corresponding to the code of the virtual key.
pub fn vk_to_char(key: u8) -> &'static str {
    for &(vk, char) in &VK_CHARS {
        if vk == key {
            return char;
        }
    }
    "UNKNOWN"
}

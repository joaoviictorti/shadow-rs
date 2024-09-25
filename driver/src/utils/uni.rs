use alloc::vec::Vec;
use wdk_sys::UNICODE_STRING;

/// A wrapper around a `Vec<u16>` representing a Unicode string.
///
/// This struct encapsulates a Unicode string, stored as a `Vec<u16>`, that is compatible
/// with the Windows kernel's `UNICODE_STRING` structure. It ensures that the string is properly
/// null-terminated and provides a safe conversion method to a `UNICODE_STRING`.
#[derive(Default)]
pub struct OwnedUnicodeString {
    /// The internal buffer holding the wide (UTF-16) string, including the null terminator.
    buffer: Vec<u16>,
    /// A marker to indicate that this struct cannot be moved once pinned.
    /// This ensures that the memory address of the buffer remains valid for the lifetime of the
    /// `UNICODE_STRING`.
    _phantompinned: core::marker::PhantomPinned,
}

impl OwnedUnicodeString {
    /// Converts the `OwnedUnicodeString` into a `UNICODE_STRING` that can be used in kernel APIs.
    ///
    /// This function creates a `UNICODE_STRING` structure from the internal buffer of the `OwnedUnicodeString`.
    /// It correctly calculates the length and maximum length fields of the `UNICODE_STRING`, which represent
    /// the size of the string (in bytes) excluding and including the null terminator, respectively.
    ///
    /// # Returns
    /// 
    /// - A `UNICODE_STRING` pointing to the wide string stored in `buffer`.
    /// 
    pub fn to_unicode(&self) -> UNICODE_STRING {
        // The length is the size of the string in bytes, excluding the null terminator.
        // MaximumLength includes the null terminator.
        UNICODE_STRING {
            Length: ((self.buffer.len() * core::mem::size_of::<u16>()) - 2) as u16,
            MaximumLength: (self.buffer.len() * core::mem::size_of::<u16>()) as u16,
            Buffer: self.buffer.as_ptr() as *mut u16,
        }
    }
}

/// Converts a Rust `&str` to an `OwnedUnicodeString`.
///
/// This function takes a Rust string slice, converts it to a wide string (UTF-16), and ensures it
/// is properly null-terminated. The resulting wide string is stored in an `OwnedUnicodeString`,
/// which can later be converted to a `UNICODE_STRING` for use in kernel APIs.
///
/// # Parameters
/// 
/// - `s`: A reference to the Rust string slice to be converted.
///
/// # Returns
/// 
/// - `OwnedUnicodeString`: A structure containing the wide (UTF-16) representation of the input string.
///
pub fn str_to_unicode(s: &str) -> OwnedUnicodeString {
    // Convert the rust string to a wide string
    let mut wide_string: Vec<u16> = s.encode_utf16().collect();
    wide_string.push(0); // Null terminate the string
    OwnedUnicodeString {
        buffer: wide_string,
        _phantompinned: core::marker::PhantomPinned,
    }
}

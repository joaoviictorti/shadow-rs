use alloc::vec::Vec;
use wdk_sys::UNICODE_STRING;

/// A wrapper around a Vec<u16> that represents a unicode string
#[derive(Default)]
pub(crate) struct OwnedUnicodeString {
    ///
    buffer: Vec<u16>,
    ///
    _phantompinned: core::marker::PhantomPinned,
}

impl OwnedUnicodeString {
    /// Convert the OwnedUnicodeString to a UNICODE_STRING.
    /// SAFETY: `self` must be pinned and remain valid for the lifetime of the UNICODE_STRING.
    pub(crate) fn to_unicode(&self) -> UNICODE_STRING {
        // Note: we subtract 2 from the length to account for the u16 null terminator, as the length field is the length of the string minus the null terminator.
        UNICODE_STRING {
            Length: ((self.buffer.len() * core::mem::size_of::<u16>()) - 2) as u16,
            MaximumLength: (self.buffer.len() * core::mem::size_of::<u16>()) as u16,
            Buffer: self.buffer.as_ptr() as *mut u16,
        }
    }
}

/// Creates a new OwnedUnicodeString from a rust string. The string is converted to a wide string and null-terminated.
/// 
/// 
/// 
pub(crate) fn str_to_unicode(s: &str) -> OwnedUnicodeString {
    // Convert the rust string to a wide string
    let mut wide_string: Vec<u16> = s.encode_utf16().collect();
    wide_string.push(0); // Null terminate the string
    OwnedUnicodeString {
        buffer: wide_string,
        _phantompinned: core::marker::PhantomPinned,
    }
}

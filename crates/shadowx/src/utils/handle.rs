use wdk_sys::{ntddk::ZwClose, HANDLE};

/// A wrapper around a Windows `HANDLE` that automatically closes the handle when dropped.
///
/// This struct provides a safe abstraction over raw Windows handles, ensuring that the
/// handle is properly closed when it goes out of scope, by calling `ZwClose` in its `Drop`
/// implementation.
pub struct Handle(HANDLE);

impl Handle {
    /// Creates a new `Handle` instance.
    ///
    /// This function wraps a raw Windows `HANDLE` inside the `Handle` struct.
    ///
    /// # Arguments
    /// 
    /// * `handle` - A raw Windows `HANDLE` to wrap.
    ///
    /// # Returns
    /// 
    /// * Returns a new `Handle` instance that encapsulates the provided raw `HANDLE`.
    #[inline]
    pub fn new(handle: HANDLE) -> Self {
        Handle(handle)
    }
    
    /// Returns the raw `HANDLE`.
    ///
    /// This function provides access to the underlying Windows handle
    /// stored in the `Handle` struct.
    ///
    /// # Returns
    /// 
    /// * Returns the raw Windows `HANDLE` encapsulated in the `Handle` struct.
    #[inline]
    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    /// Automatically closes the `HANDLE` when the `Handle` instance is dropped.
    ///
    /// When the `Handle` goes out of scope, this method is called to ensure that
    /// the underlying Windows handle is closed using the `ZwClose` function, unless
    /// the handle is null.
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                ZwClose(self.0);
            }
        }
    }
}
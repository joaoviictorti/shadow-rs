use wdk_sys::{ntddk::ZwClose, HANDLE};

pub struct Handle(HANDLE);

impl Handle {
    /// Create new instance `Handle`.
    #[inline]
    pub fn new(handle: HANDLE) -> Self {
        Handle(handle)
    }
    
    /// Return handle.
    #[inline]
    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    #[inline]
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                ZwClose(self.0);
            }
        }
    }
}
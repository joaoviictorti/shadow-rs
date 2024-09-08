use core::ffi::c_void;
use wdk_sys::{ntddk::{ExAllocatePool2, ExFreePool}, POOL_FLAGS};

pub struct PoolMemory {
    pub ptr: *mut c_void,
}

impl PoolMemory {
    #[inline]
    pub fn new(flag: POOL_FLAGS, number_of_bytes: u64, tag: u32) -> Option<PoolMemory> {
        let ptr = unsafe { ExAllocatePool2(flag, number_of_bytes, tag) };
        if ptr.is_null() {
            None
        } else {
            Some(PoolMemory {
                ptr,
            })
        }
    }
}

impl Drop for PoolMemory {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ExFreePool(self.ptr) };
        }
    }
}
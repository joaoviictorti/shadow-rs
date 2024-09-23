use core::ffi::c_void;
use wdk_sys::{ntddk::{ExAllocatePool2, ExFreePool}, POOL_FLAGS};

/// A wrapper around memory allocated from the pool in the Windows kernel.
///
/// This struct provides a safe abstraction over memory allocated from the kernel pool.
/// It ensures that the allocated memory is properly freed when the `PoolMemory` goes out
/// of scope, by calling `ExFreePool` in its `Drop` implementation.
/// 
pub struct PoolMemory {
    /// A raw pointer to the allocated pool memory.
    pub ptr: *mut c_void,
}

impl PoolMemory {
    /// Allocates memory from the Windows kernel pool.
    ///
    /// This function uses `ExAllocatePool2` to allocate a block of memory from the Windows kernel
    /// pool. It returns `None` if the allocation fails, or `Some(PoolMemory)` if successful.
    ///
    /// # Parameters
    /// - `flag`: Flags controlling the behavior of the memory allocation, of type `POOL_FLAGS`.
    /// - `number_of_bytes`: The size of the memory block to allocate, in bytes.
    /// - `tag`: A tag (typically a 4-character identifier) used to identify the allocation.
    ///
    /// # Returns
    /// - `Option<PoolMemory>`: `Some(PoolMemory)` if the memory is successfully allocated, or `None` if the allocation fails.
    ///
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
    /// Frees the allocated pool memory when the `PoolMemory` instance is dropped.
    ///
    /// This method is automatically called when the `PoolMemory` goes out of scope. It ensures that
    /// the memory allocated with `ExAllocatePool2` is properly freed using `ExFreePool`, unless
    /// the pointer is null.
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ExFreePool(self.ptr) };
        }
    }
}
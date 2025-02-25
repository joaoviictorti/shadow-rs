use core::ffi::c_void;
use wdk_sys::{
    ntddk::{ExAllocatePool2, ExFreePool},
    POOL_FLAGS,
};

/// A wrapper around memory allocated from the pool in the Windows kernel.
///
/// This struct provides a safe abstraction over memory allocated from the kernel pool.
/// It ensures that the allocated memory is properly freed when the `PoolMemory` goes out
/// of scope, by calling `ExFreePool` in its `Drop` implementation.
pub struct PoolMemory {
    /// A raw pointer to the allocated pool memory.
    pub ptr: *mut c_void,
}

impl PoolMemory {
    /// Allocates memory from the Windows kernel pool.
    ///
    /// # Arguments
    ///
    /// * `flag` - Flags controlling memory allocation behavior (e.g., paged or non-paged memory).
    /// * `number_of_bytes` - Size of the memory block to allocate (in bytes).
    /// * `tag` - A **4-character string** identifying the memory allocation.
    ///
    /// # Returns
    ///
    /// * `Some(PoolMemory)` - If memory allocation succeeds.
    /// * `None` - If memory allocation fails.
    ///
    /// # Panics
    ///
    /// This function **panics** if `tag` is not exactly 4 characters long.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let pool_mem = PoolMemory::new(POOL_FLAG_NON_PAGED, 1024, "tag1");
    /// if let Some(mem) = pool_mem {
    ///     // Use allocated memory...
    /// } else {
    ///     println!("Memory allocation failed");
    /// }
    /// ```
    #[inline]
    pub fn new(flag: POOL_FLAGS, number_of_bytes: u64, tag: &str) -> Option<PoolMemory> {
        assert!(tag.len() == 4, "Pool tag must be exactly 4 characters long");

        // Convert the string into a 4-byte integer (u32)
        let tag_bytes = tag.as_bytes();
        let tag = u32::from_ne_bytes([tag_bytes[0], tag_bytes[1], tag_bytes[2], tag_bytes[3]]);

        let ptr = unsafe { ExAllocatePool2(flag, number_of_bytes, tag) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
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

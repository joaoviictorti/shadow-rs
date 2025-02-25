use core::alloc::{GlobalAlloc, Layout};
use wdk_sys::{ntddk::{ExAllocatePool2, ExFreePool}, POOL_FLAG_NON_PAGED};

#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAlloc = KernelAlloc;

/// Standard memory allocator for kernel space.
///
/// Utilizes `ExAllocatePool2` from the WDK for memory operations.
struct KernelAlloc;

// The value of memory tags are stored in little-endian order, so it is
// convenient to reverse the order for readability in tooling (ie. Windbg)
const RUST_TAG: u32 = u32::from_ne_bytes(*b"rust");

unsafe impl GlobalAlloc for KernelAlloc {
    /// Allocates a block of memory in the kernel space.
    ///
    /// This function leverages the `ExAllocatePool2` function from the WDK to
    /// provide memory allocation capabilities.
    ///
    /// # Parameters
    ///
    /// * `layout` - Memory layout specifications.
    ///
    /// # Returns
    ///
    /// * A raw pointer to the allocated block of memory.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, layout.size() as u64, RUST_TAG);
        if memory.is_null() {
            return core::ptr::null_mut();
        }
    
        memory.cast()
    }

    /// Frees a previously allocated block of memory in the kernel space.
    ///
    /// This function leverages the `ExFreePool` function from the WDK to
    /// release the memory back to the system.
    ///
    /// # Parameters
    ///
    /// * `ptr` - Raw pointer to the memory block to be released.
    /// * `_layout` - Memory layout specifications (not used in this implementation).
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        ExFreePool(ptr.cast());
    }
}
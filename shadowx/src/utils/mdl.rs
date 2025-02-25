use core::ptr::null_mut;
use wdk_sys::ntddk::{
    IoAllocateMdl, IoFreeMdl, 
    MmMapLockedPagesSpecifyCache, 
    MmProbeAndLockPages, MmUnlockPages, 
    MmUnmapLockedPages
};
use wdk_sys::{
    MdlMappingNoExecute, MDL, PUCHAR, 
    _LOCK_OPERATION::IoModifyAccess, 
    _MEMORY_CACHING_TYPE::MmCached, 
    _MM_PAGE_PRIORITY::HighPagePriority, 
    _MODE::KernelMode
};

/// Memory Descriptor List (MDL) wrapper for safe kernel memory modification.
///
/// This struct encapsulates an MDL to safely lock, map, and modify memory regions.
pub struct Mdl {
    /// Pointer to the MDL structure.
    mdl: *mut MDL,

    /// Mapped kernel address of the locked memory.
    mapped_address: PUCHAR,
}

impl Mdl {
    /// Creates a new MDL for modifying kernel memory.
    ///
    /// This function allocates an MDL, locks the memory pages, and maps them
    /// for kernel access.
    ///
    /// # Arguments
    /// 
    /// * `dest` - Target memory address to be modified.
    /// * `size` - Size of the memory region to lock.
    ///
    /// # Returns
    /// 
    /// * `Some(Mdl)` - On success.
    /// * `None` - If allocation or mapping fails.
    pub fn new(dest: *const u8, size: usize) -> Option<Self> {
        if dest.is_null() || size == 0 {
            wdk::println!("Invalid Parameters");
            return None;
        }

        unsafe {
            // Allocate an MDL
            let mdl = IoAllocateMdl(dest as _, size as u32, 0, 0, null_mut());
            if mdl.is_null() {
                return None;
            }

            // Lock the pages for modification
            MmProbeAndLockPages(mdl, KernelMode as i8, IoModifyAccess);

            // Map the locked pages for kernel access
            let mapped_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode as i8, MmCached, null_mut(), 0, HighPagePriority as u32 | MdlMappingNoExecute) as *mut u8;
            if mapped_address.is_null() {
                wdk::println!("Failed to map blocked pages");
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                return None;
            }

            Some(Self { mdl, mapped_address })
        }
    }

    /// Copies memory to the mapped address.
    ///
    /// # Arguments
    /// 
    /// * `src` - Pointer to the source data.
    /// * `size` - Size of the data to copy.
    pub fn copy(&self, src: *const u8, size: usize) {
        if src.is_null() || self.mapped_address.is_null() {
            wdk::println!("Invalid address in the memory copy.");
            return;
        }

        unsafe {
            core::ptr::copy_nonoverlapping(src, self.mapped_address, size);
        }
    }
}

impl Drop for Mdl {
    /// Cleans up the MDL and releases memory when dropped.
    fn drop(&mut self) {
        unsafe {
            if !self.mapped_address.is_null() {
                MmUnmapLockedPages(self.mapped_address as _, self.mdl);
            }

            if !self.mdl.is_null() {
                MmUnlockPages(self.mdl);
                IoFreeMdl(self.mdl);
            }
        }
    }
}
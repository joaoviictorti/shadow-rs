use wdk_sys::ntddk::{ExAcquirePushLockExclusiveEx, ExReleasePushLockExclusiveEx};

/// Generic function that performs the operation with the lock already acquired.
/// It will acquire the lock exclusively and guarantee its release after use.
///
/// # Arguments
///
/// * `push_lock` - Pointer to the lock to be acquired.
/// * `operation` - The operation to be performed while the lock is active.
pub fn with_push_lock_exclusive<T, F>(push_lock: *mut u64, operation: F) -> T
where
    F: FnOnce() -> T,
{
    unsafe {
        // Get the lock exclusively
        ExAcquirePushLockExclusiveEx(push_lock, 0);
    }

    // Performs the operation while the lock is active
    let result = operation();

    unsafe {
        // Releases the lock after the operation
        ExReleasePushLockExclusiveEx(push_lock, 0);
    }

    result
}

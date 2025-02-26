use wdk_sys::ntddk::{ExAcquirePushLockExclusiveEx, ExAcquireResourceSharedLite, ExReleasePushLockExclusiveEx};
use wdk_sys::ntddk::{ExAcquireResourceExclusiveLite, ExReleaseResourceLite};
use wdk_sys::ERESOURCE;

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

/// Executes an operation while holding an `ERESOURCE` lock.
///
/// # Arguments
/// 
/// * `resource` - Pointer to the `ERESOURCE` lock.
/// * `operation` - The function to execute while holding the lock.
pub fn with_eresource_exclusive_lock<T, F>(resource: *mut ERESOURCE, operation: F) -> T
where
    F: FnOnce() -> T,
{
    unsafe {
        // Acquire the exclusive lock before accessing the resource
        ExAcquireResourceExclusiveLite(resource, 1);
    }

    // Execute the operation while holding the lock
    let result = operation();

    unsafe {
        // Release the lock after the operation
        ExReleaseResourceLite(resource);
    }

    result
}

/// Executes an operation while holding a **shared** ERESOURCE lock.
/// This allows multiple threads to read concurrently, but no writes can occur.
///
/// # Arguments
///
/// * `resource` - Pointer to the `ERESOURCE` lock.
/// * `operation` - The function to execute while holding the lock.
///
/// # Returns
///
/// The result of the operation executed within the lock.
pub fn with_eresource_shared_lock<T, F>(resource: *mut ERESOURCE, operation: F) -> T
where
    F: FnOnce() -> T,
{
    unsafe {
        // Acquire the shared lock before accessing the resource
        ExAcquireResourceSharedLite(resource, 1);
    }

    // Execute the operation while holding the lock
    let result = operation();

    unsafe {
        // Release the shared lock
        ExReleaseResourceLite(resource);
    }

    result
}
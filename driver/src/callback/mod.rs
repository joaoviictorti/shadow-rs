use {
    alloc::vec::Vec,
    crate::includes::structs::{CallbackRestaure, CallbackRestaureOb}, 
    shared::structs::{CallbackInfoInput, CallbackInfoOutput}, 
    spin::{lazy::Lazy, Mutex}, wdk_sys::NTSTATUS, 
};

mod find_callback;
pub mod ioctls;
pub mod callbacks;

/// Variable that stores callbacks that have been removed.
pub static mut INFO_CALLBACK_RESTAURE: Lazy<Mutex<Vec<CallbackRestaure>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(40)));

/// Variable that stores callbacks registry that have been removed.
static mut INFO_CALLBACK_RESTAURE_REGISTRY: Lazy<Mutex<Vec<CallbackRestaure>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(40)));

/// Variable that stores callbacks Ob that have been removed.
static mut INFO_CALLBACK_RESTAURE_OB: Lazy<Mutex<Vec<CallbackRestaureOb>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(40)));

/// Trait defining common operations for callback lists.
pub trait CallbackList {
    /// Restore a callback from the specified routine.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn restore_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS;

    /// Removes a callback from the specified routine.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn remove_callback(target_callback: *mut CallbackInfoInput) -> NTSTATUS;

    /// Searches for a module associated with a callback and updates callback information.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// - `callback_info`: Pointer to the callback information output.
    /// - `information`: Pointer to a variable to store information size.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn enumerate_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> Result<(), NTSTATUS>;

    /// List of callbacks currently removed.
    /// 
    /// # Parameters
    /// - `target_callback`: Pointer to the callback information input.
    /// - `callback_info`: Pointer to the callback information output.
    /// - `information`: Pointer to a variable to store information size.
    /// 
    /// # Returns
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    ///
    unsafe fn enumerate_removed_callback(target_callback: *mut CallbackInfoInput, callback_info: *mut CallbackInfoOutput, information: &mut usize) -> Result<(), NTSTATUS>;
}


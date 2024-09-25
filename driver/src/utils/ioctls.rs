use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    lazy_static::lazy_static,
    wdk_sys::{IO_STACK_LOCATION, IRP, NTSTATUS},
    crate::{
        callback::ioctls::get_callback_ioctls, 
        driver::ioctls::get_driver_ioctls, 
        process::ioctls::get_process_ioctls, 
        thread::ioctls::get_thread_ioctls,
        registry::ioctls::get_registry_ioctls,
        injection::ioctls::get_injection_ioctls,
        misc::ioctls::get_misc_ioctls,
        module::ioctls::get_module_ioctls,
        port::ioctls::get_port_ioctls,
    },
};

/// Type alias for an IOCTL handler function.
///
/// This type represents a boxed function that handles IOCTL requests. Each handler takes
/// two parameters, `IRP` (I/O Request Packet) and `IO_STACK_LOCATION`, and returns
/// an `NTSTATUS` result, indicating the success or failure of the operation.
///
/// # Parameters
/// 
/// - `*mut IRP`: Pointer to an IRP (I/O Request Packet), which represents an I/O request in Windows.
/// - `*mut IO_STACK_LOCATION`: Pointer to the current I/O stack location.
/// 
/// 
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
pub type IoctlHandler = Box<dyn Fn(*mut IRP, *mut IO_STACK_LOCATION) -> NTSTATUS + Send + Sync>;

lazy_static! {
    /// A static map that holds the mapping of IOCTL codes to their corresponding handlers.
    pub static ref IOCTL_MAP: HashMap<u32, IoctlHandler> = load_ioctls();
}

/// Loads the IOCTL handlers into a `HashMap`.
///
/// This function collects IOCTL handlers from various modules and inserts them
/// into a `HashMap`, which maps IOCTL codes (`u32`) to their respective handler functions (`IoctlHandler`).
///
/// # Returns
/// 
/// - `HashMap<u32, IoctlHandler>`: A map containing IOCTL handlers for process, thread, driver,
///   callback, injection, miscellaneous, module, and port operations.
///   If the "mapper" feature is disabled, registry-related IOCTLs are also included.
/// 
fn load_ioctls() -> HashMap<u32, IoctlHandler> {
    let mut ioctls = HashMap::new();

    get_process_ioctls(&mut ioctls);
    get_thread_ioctls(&mut ioctls);
    get_driver_ioctls(&mut ioctls);
    get_callback_ioctls(&mut ioctls);
    get_injection_ioctls(&mut ioctls);
    get_misc_ioctls(&mut ioctls);
    get_module_ioctls(&mut ioctls);
    get_port_ioctls(&mut ioctls);

    #[cfg(not(feature = "mapper"))] {
        get_registry_ioctls(&mut ioctls);
    }

    ioctls
}

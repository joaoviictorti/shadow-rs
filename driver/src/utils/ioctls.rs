use {
    crate::modules::*,
    alloc::boxed::Box, 
    shadowx::error::ShadowError, 
    wdk_sys::{IO_STACK_LOCATION, IRP, NTSTATUS},
};

/// Type alias for an IOCTL handler function.
///
/// This type represents a boxed function that handles IOCTL requests. Each handler takes
/// two parameters, `IRP` (I/O Request Packet) and `IO_STACK_LOCATION`, and returns
/// an `NTSTATUS` result, indicating the success or failure of the operation.
///
/// # Arguments
/// 
/// * `*mut IRP` - Pointer to an IRP (I/O Request Packet), which represents an I/O request in Windows.
/// * `*mut IO_STACK_LOCATION` - Pointer to the current I/O stack location.
/// 
/// # Returns
/// 
/// * `NTSTATUS` - A status code indicating the success or failure of the operation.
pub type IoctlHandler = Box<dyn Fn(*mut IRP, *mut IO_STACK_LOCATION) -> Result<NTSTATUS, ShadowError> + Send + Sync>;

pub struct IoctlManager {
    handlers: hashbrown::HashMap<u32, IoctlHandler>,
}

impl IoctlManager {
    /// Registers a new IOCTL handler.
    pub fn register_handler(&mut self, code: u32, handler: IoctlHandler) {
        self.handlers.insert(code, handler);
    }

    /// Retrieves the IOCTL handler for the given control code.
    pub fn get_handler(&self, control_code: u32) -> Option<&IoctlHandler> {
        self.handlers.get(&control_code)
    }

    /// Loads the IOCTL handlers into a `HashMap`.
    ///
    /// This function collects IOCTL handlers from various modules and inserts them
    /// into a `HashMap`, which maps IOCTL codes (`u32`) to their respective handler functions (`IoctlHandler`).
    pub fn load_default_handlers(&mut self) {
        register_process_ioctls(self);
        register_thread_ioctls(self);
        register_driver_ioctls(self);
        register_callback_ioctls(self);
        register_injection_ioctls(self);
        register_misc_ioctls(self);
        register_module_ioctls(self);
        register_port_ioctls(self);
        
        #[cfg(not(feature = "mapper"))]
        {
            crate::modules::register_registry_ioctls(self);
        }
    }
}

impl Default for IoctlManager {
    /// Creates a new IoctlManager with an empty handler map.
    fn default() -> Self {
        Self {
            handlers: hashbrown::HashMap::new(),
        }
    }
}

use {
    alloc::boxed::Box, 
    hashbrown::HashMap,
    lazy_static::lazy_static,
    wdk_sys::{IO_STACK_LOCATION, IRP, NTSTATUS},
    crate::{
        callbacks::ioctls::get_callback_ioctls, 
        driver::ioctls::get_driver_ioctls, 
        process::ioctls::get_process_ioctls, 
        thread::ioctls::get_thread_ioctls,
        registry::ioctls::get_registry_ioctls,
        injection::ioctls::get_injection_ioctls,
        misc::ioctls::get_misc_ioctls,
        module::ioctls::get_module_ioctls,
    },
};

pub type IoctlHandler = Box<dyn Fn(*mut IRP, *mut IO_STACK_LOCATION) -> NTSTATUS + Send + Sync>;

lazy_static! {
    pub static ref IOCTL_MAP: HashMap<u32, IoctlHandler> = load_ioctls();
}

fn load_ioctls() -> HashMap<u32, IoctlHandler> {
    let mut ioctls = HashMap::new();

    get_process_ioctls(&mut ioctls);
    get_thread_ioctls(&mut ioctls);
    get_driver_ioctls(&mut ioctls);
    get_callback_ioctls(&mut ioctls);
    get_injection_ioctls(&mut ioctls);
    get_misc_ioctls(&mut ioctls);
    get_module_ioctls(&mut ioctls);

    #[cfg(not(feature = "mapper"))] {
        get_registry_ioctls(&mut ioctls);
    }

    ioctls
}
